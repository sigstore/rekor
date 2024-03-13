#!/bin/bash
#
# Copyright 2024 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

set -o errexit

cleanup() {
    code=$?
    if [ $code -ne 0 ] ; then
        echo "An error occurred. Waiting 30 seconds to start cleanup, press ^C to cancel cleanup."
        sleep 30
    fi
    $@
    exit $code
}

INSERT_RUNS=${INSERT_RUNS:-1000}
SEARCH_ENTRIES=${SEARCH_ENTRIES:-100000}
INDEX_BACKEND=${INDEX_BACKEND:-redis}
REGION=${REGION:-us-west1}

setup_bastion() {
    echo "Configuring the bastion..."
    sudo apt install kubernetes-client google-cloud-sdk-gke-gcloud-auth-plugin git redis-tools gnuplot prometheus minisign jq -y
    if ! which hyperfine >/dev/null ; then
        local tag=$(curl -H "Accept: application/json" -L https://github.com/sharkdp/hyperfine/releases/latest | jq -r .tag_name)
        wget -O /tmp/hyperfine_${tag:1}_amd64.deb https://github.com/sharkdp/hyperfine/releases/download/${tag}/hyperfine_${tag:1}_amd64.deb
        sudo dpkg -i /tmp/hyperfine_${tag:1}_amd64.deb
    fi
    if ! which helm >/dev/null ; then
        curl https://raw.githubusercontent.com/helm/helm/main/scripts/get-helm-3 | bash
    fi
    if ! which rekor-cli >/dev/null ; then
        wget -O /tmp/rekor-cli-linux-amd64 https://github.com/sigstore/rekor/releases/latest/download/rekor-cli-linux-amd64
        sudo install -m 0755 /tmp/rekor-cli-linux-amd64 /usr/local/bin/rekor-cli
    fi
    gcloud auth print-access-token >/dev/null 2>&1 || gcloud auth login
    gcloud container clusters get-credentials rekor --region $REGION
}

setup_rekor() {
    echo "Setting up rekor..."
    helm repo add sigstore https://sigstore.github.io/helm-charts
    helm repo update

    sha=$(git ls-remote https://github.com/sigstore/rekor HEAD | awk '{print substr($1, 1, 7)}')
    cat >values.yaml <<EOF
server:
  ingress:
    enabled: false
  image:
    repository: projectsigstore/rekor/ci/rekor/rekor-server
    version: '$sha'
EOF

    if [ "$INDEX_BACKEND" == "redis" ] ; then
        export REDIS_IP=$(gcloud redis instances describe rekor-index --region $REGION --format='get(host)')
        cat >index-values.yaml <<EOF
redis:
  enabled: false
  hostname: $REDIS_IP
server:
  extraArgs:
    - --search_index.storage_provider=redis
EOF
        helm upgrade -i rekor sigstore/rekor -n rekor-system --create-namespace --values values.yaml --values index-values.yaml
        kubectl -n rekor-system rollout status deploy rekor-server
    else
        export MYSQL_IP=$(gcloud sql instances describe rekor-perf-tf --format='get(ipAddresses[0].ipAddress)')
        cat >index-values.yaml <<EOF
server:
  extraArgs:
    - --search_index.storage_provider=mysql
    - --search_index.mysql.dsn=trillian:\$(MYSQL_PASSWORD)@tcp(${MYSQL_IP}:3306)/trillian
EOF
        helm upgrade -i rekor sigstore/rekor -n rekor-system --create-namespace --values values.yaml --values mysql-args-values.yaml
        echo -n $MYSQL_PASS | kubectl -n rekor-system create secret generic mysql-credentials --save-config --dry-run=client --output=yaml --from-file=mysql-password=/dev/stdin | kubectl apply -f -
        cat > patch.yaml <<EOF
spec:
  template:
    spec:
      containers:
      - name: rekor-server
        env:
        - name: MYSQL_PASSWORD
          valueFrom:
            secretKeyRef:
              name: mysql-credentials
              key: mysql-password
EOF
        kubectl -n rekor-system patch deployment rekor-server --patch-file=patch.yaml
        kubectl -n rekor-system rollout status deploy rekor-server
    fi
    kubectl apply -f - <<EOF
apiVersion: v1
kind: Service
metadata:
  name: rekor-server-nodeport
  namespace: rekor-system
spec:
  selector:
    app.kubernetes.io/component: server
    app.kubernetes.io/instance: rekor
    app.kubernetes.io/name: rekor
  ports:
  - name: http
    port: 80
    protocol: TCP
    targetPort: 3000
    nodePort: 30080
  - name: metrics
    port: 2112
    protocol: TCP
    targetPort: 2112
    nodePort: 32112
  type: NodePort
EOF

    node_address=$(kubectl get node -o jsonpath='{.items[0].status.addresses[?(@.type=="InternalIP")].address}')
    export REKOR_URL=http://${node_address}:30080
    export REKOR_METRICS=${node_address}:32112
}

setup_prometheus() {
    echo "Setting up prometheus..."
    sudo systemctl disable --now prometheus
    mkdir -p prometheus >/dev/null
    rm -rf prometheus/metrics2
    cat >prometheus/prometheus.yml <<EOF
scrape_configs:
  - job_name: 'prometheus'
    scrape_interval: 1s
    static_configs:
      - targets:
          - '$REKOR_METRICS'
EOF
    setsid prometheus --storage.tsdb.path=./prometheus/metrics2 --config.file=prometheus/prometheus.yml >prometheus/prom.log 2>&1 &
    export PROM_PID=$!
}

# Upload $INSERT_RUNS rekords of $INSERT_RUNS artifacts signed by 1 key
insert() {
    echo "Inserting entries..."
    local N=$INSERT_RUNS
    # Create N artifacts with different contents
    export DIR=$(mktemp -d)
    for i in $(seq 1 $N) ; do
        echo hello${i} > ${DIR}/blob${i}
    done
    # Create a signing key
    minisign -G -p $DIR/user1@example.com.pub -s $DIR/user1@example.com.key -W >/dev/null

    echo "Signing $N artifacts with 1 key"
    user=user1@example.com
    local batch=0
    while [ $batch -lt $N ] ; do
        for i in $(seq 1 100) ; do
            let id=$batch+$i
            if [ $id -gt $N ] ; then
                break
            fi
            sig=${DIR}/$(uuidgen).asc
            (
                minisign -S -x $sig -s $DIR/$user.key -m ${DIR}/blob${id}
                rekor-cli upload --rekor_server $REKOR_URL --signature $sig --public-key ${DIR}/${user}.pub --artifact ${DIR}/blob${id} --pki-format=minisign
            ) &
        done
        wait $(jobs -p | grep -v $PROM_PID)
        let batch+=100
    done

    rm -rf $DIR
}

query_inserts() {
    echo "Getting metrics for inserts..."
    count=null

    # may need to wait for the data to be scraped
    tries=0
    until [ "${count}" != "null" ] ; do
        sleep 1
        count=$(curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_index_storage_latency_summary_count{success="true"}' | jq -r .data.result[0].value[1])
        let 'tries+=1'
        if [ $tries -eq 6 ] ; then
            echo "count query failed, here is the raw result:"
            set -x
            curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_index_storage_latency_summary_count{success="true"}'
            set +x
            echo
            exit 1
        fi
    done

    avg=$(curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_index_storage_latency_summary_sum{success="true"}/rekor_index_storage_latency_summary_count{success="true"}' | jq -r .data.result[0].value[1])

    if [ "${avg}" == "null" ] ; then
        echo "avg query failed, here is the raw result:"
        set -x
        curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_index_storage_latency_summary_sum{success="true"}/rekor_index_storage_latency_summary_count{success="true"}'
        set +x
        echo
        exit 1
    fi

    echo "Insert latency: ${avg} (average over ${count} inserts)"
    results=${INDEX_BACKEND}.dat
    if [ "$INDEX_BACKEND" == "redis" ] ; then
        x=1
    else
        x=0
    fi
    # output to gnuplot data set
    echo "$x \"${INDEX_BACKEND} inserts\n(${count})\" $avg" > $results
}

upload() {
    echo "Uploading entries..."
    N=$SEARCH_ENTRIES

    if [ ! -f indices.csv ] ; then
        echo "Generating $N * 2 entries. This may take a while..."
        # N artifacts, 1 user
        for i in $(seq 1 $N) ; do
            uuid=$(dbus-uuidgen)
            echo user1@example.com,$uuid >> indices.csv
            sha=$(echo $i | sha256sum | cut -d ' ' -f 1)
            echo sha256:$sha,$uuid >> indices.csv
        done

        # 1 artifact, N users
        sha=$(echo 1 | sha256sum | cut -d ' ' -f 1)
        for i in $(seq 2 $N) ; do
            uuid=$(dbus-uuidgen)
            echo user${i}@example.com,$uuid >> indices.csv
            echo sha256:$sha,$uuid >> indices.csv
        done
    fi

    if [ "${INDEX_BACKEND}" == "redis" ] ; then
        local dbsize=$(redis-cli -h $REDIS_IP dbsize | cut -d ' ' -f 2)
        let wantsize=$SEARCH_ENTRIES*2
        if [ ! $dbsize -ge $wantsize ] ; then
            echo "Uploading entries into redis..."
            while read LINE ; do
                key=$(echo $LINE | cut -d',' -f1)
                val=$(echo $LINE | cut -d',' -f2)
                printf "*3\r\n\$5\r\nLPUSH\r\n\$${#key}\r\n${key}\r\n\$${#val}\r\n${val}\r\n"
            done < indices.csv | redis-cli -h $REDIS_IP --pipe
        fi
    else
        local dbsize=$(mysql -h $MYSQL_IP -P 3306 -utrillian -p${MYSQL_PASS} -D trillian -e "SELECT COUNT(*) FROM EntryIndex" --vertical | tail -1 | cut -d ' ' -f 2)
        let wantsize=$SEARCH_ENTRIES*4
        if [ ! $dbsize -ge $wantsize ] ; then
            echo "Uploading entries into mysql..."
            mysql -h $MYSQL_IP -P 3306 -utrillian -p${MYSQL_PASS} -D trillian -e "CREATE TABLE IF NOT EXISTS EntryIndex (
                    PK BIGINT UNSIGNED NOT NULL AUTO_INCREMENT,
                    EntryKey varchar(512) NOT NULL,
                    EntryUUID char(80) NOT NULL,
                    PRIMARY KEY(PK),
                    UNIQUE(EntryKey, EntryUUID)
            );
            LOAD DATA LOCAL INFILE './indices.csv'
            INTO TABLE EntryIndex
            FIELDS TERMINATED BY ','
            LINES TERMINATED BY '\n' (EntryKey, EntryUUID);"
        fi
    fi
}

search() {
    echo "Running search requests..."
    sumblob1=$(echo 1 | sha256sum | cut -d ' ' -f1)
    sumblob2=$(echo 2 | sha256sum | cut -d ' ' -f1)
    sumblobnone=$(echo none | sha256sum | cut -d ' ' -f1)
    # Search for entries using public key user1@example.com (should be many), user2@example.com (should be few), notreal@example.com (should be none)
    hyperfine --style basic --warmup 10 --ignore-failure --parameter-list email user1@example.com,user2@example.com,notreal@example.com "rekor-cli search --rekor_server $REKOR_URL --email {email}"
    # Search for entries using the sha256 sum of blob1 (should be many), blob2 (should be few), blobnone (should be none)
    hyperfine --style basic --warmup 10 --ignore-failure --parameter-list sha ${sumblob1},${sumblob2},${sumblobnone} "rekor-cli search --rekor_server $REKOR_URL --sha sha256:{sha}"
    # Search for entries using public key user1@example.com/user2@example.com/notreal@example.com OR/AND sha256 sum of blob1/blob2/blobnone
    hyperfine --style basic --warmup 10 --ignore-failure --parameter-list email user1@example.com,user2@example.com,notreal@example.com \
        --parameter-list sha ${sumblob1},${sumblob2},${sumblobnone} \
        --parameter-list operator or,and \
        "rekor-cli search --rekor_server $REKOR_URL --email {email} --sha sha256:{sha} --operator {operator}"
}

query_search() {
    echo "Getting metrics for searches..."
    count=null
    # may need to wait for the data to be scraped
    tries=0
    until [ "${count}" != "null" ] ; do
        sleep 1
        count=$(curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_api_latency_summary_count{path="/api/v1/index/retrieve"}' | jq -r .data.result[0].value[1])
        let 'tries+=1'
        if [ $tries -eq 6 ] ; then
            echo "count query failed, here is the raw result:"
            set -x
            curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_api_latency_summary_count{path="/api/v1/index/retrieve"}'
            set +x
            echo
        fi
    done

    avg=$(curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_api_latency_summary_sum{path="/api/v1/index/retrieve"}/rekor_api_latency_summary_count{path="/api/v1/index/retrieve"}' | jq -r .data.result[0].value[1])
    if [ "${avg}" == "null" ] ; then
        echo "avg query failed, here is the raw result:"
        set -x
        curl -s http://localhost:9090/api/v1/query --data-urlencode 'query=rekor_api_latency_summary_sum{path="/api/v1/index/retrieve"}/rekor_api_latency_summary_count{path="/api/v1/index/retrieve"}'
        set +x
        echo
    fi

    echo "Search latency: ${avg} (average over ${count} searches)"
    results=${INDEX_BACKEND}.dat
    if [ "$INDEX_BACKEND" == "redis" ] ; then
        x=3
    else
        x=2
    fi
    # output to gnuplot data set
    echo "$x \"${INDEX_BACKEND} searches\n(${count})\" $avg" >> $results
}

reset() {
    echo "Resetting data..."
    if [ "${INDEX_BACKEND}" == "redis" ] ; then
        redis-cli -h $REDIS_IP flushall
    else
        mysql -h $MYSQL_IP -P 3306 -utrillian -p${MYSQL_PASS}  -D trillian -e 'DELETE FROM EntryIndex;'
    fi
    kubectl -n rekor-system rollout restart deployment rekor-server
}

if [ "${BASH_SOURCE[0]}" == "${0}" ]; then
    if [ "${INDEX_BACKEND}" != "redis" -a "${INDEX_BACKEND}" != "mysql" ] ; then
        echo '$INDEX_BACKEND must be either redis or mysql.'
        exit 1
    fi

    if [ "${INDEX_BACKEND}" == "mysql" -a "${MYSQL_PASS}" == "" ] ; then
        echo '$MYSQL_PASS must be set when $INDEX_BACKEND is mysql.'
        echo 'The trillian mysql user password can be found from your terraform host using `terraform output -json | jq -r .mysql_pass.value`.'
        exit 1
    fi

    echo "Gathering insertion and retrieval metrics for index backend [${INDEX_BACKEND}]."

    setup_bastion

    setup_rekor

    if [ -n "$RESET" ] ; then
        reset
    fi

    setup_prometheus
    cleanup_prom() {
        echo "Cleaning up prometheus..."
        pkill -x prometheus
    }
    trap 'cleanup cleanup_prom' EXIT

    insert

    query_inserts

    upload

    search

    query_search
fi
