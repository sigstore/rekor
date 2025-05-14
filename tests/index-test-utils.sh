#!/usr/bin/env bash
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

docker_compose="docker compose -f docker-compose.yml -f docker-compose.backfill-test.yml"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose -f docker-compose.yml -f docker-compose.backfill-test.yml"
fi

make_entries() {
    set -e
    # make 10 unique artifacts and sign each once
    for i in $(seq 0 9) ; do
        minisign -GW -p $testdir/mini${i}.pub -s $testdir/mini${i}.key
        echo test${i} > $testdir/blob${i}
        minisign -S -s $testdir/mini${i}.key -m $testdir/blob${i}
        local rekor_out=$(rekor-cli --rekor_server $REKOR_ADDRESS upload \
            --artifact $testdir/blob${i} \
            --pki-format=minisign \
            --public-key $testdir/mini${i}.pub \
            --signature $testdir/blob${i}.minisig \
            --format json)
        local uuid=$(echo $rekor_out | jq -r .Location | cut -d '/' -f 6)
        expected_keys["$testdir/mini${i}.pub"]=$uuid
        expected_artifacts["$testdir/blob${i}"]=$uuid
    done
    # double-sign a few artifacts
    for i in $(seq 7 9) ; do
        set +e
        let key_index=$i-5
        set -e
        minisign -S -s $testdir/mini${key_index}.key -m $testdir/blob${i}
        rekor_out=$(rekor-cli --rekor_server $REKOR_ADDRESS upload \
            --artifact $testdir/blob${i} \
            --pki-format=minisign \
            --public-key $testdir/mini${key_index}.pub \
            --signature $testdir/blob${i}.minisig \
            --format json)
        uuid=$(echo $rekor_out | jq -r .Location | cut -d '/' -f 6)
        local orig_key_uuid="${expected_keys[${testdir}/mini${key_index}.pub]}"
        expected_keys[$testdir/mini${key_index}.pub]="$orig_key_uuid $uuid"
        local orig_art_uuid="${expected_artifacts[${testdir}/blob${i}]}"
        expected_artifacts[${testdir}/blob${i}]="$orig_art_uuid $uuid"
    done
    set +e
}

cleanup() {
    rv=$?
    if [ $rv -ne 0 ] ; then
        ${docker_compose} logs --no-color > /tmp/docker-compose.log
    fi
    ${docker_compose} down --remove-orphans
    rm -rf $testdir
    exit $rv
}

docker_up () {
    set -e
    ${docker_compose} up -d --build
    local count=0
    echo "waiting up to 2 min for system to start"
    until [ $(${docker_compose} ps | \
       grep -E "(rekor[-_]mysql|rekor[-_]redis|rekor[-_]rekor-server|rekor[-_]trillian)" | \
       grep -c "(healthy)" ) == 5 ];
    do
        if [ $count -eq 24 ]; then
           echo "! timeout reached"
           exit 1
        else
           echo -n "."
           sleep 5
           let 'count+=1'
        fi
    done
    set +e
}

redis_cli() {
    set -e
    redis-cli -h $REDIS_HOST -a $REDIS_PASSWORD $@ 2>/dev/null
    set +e
}

mysql_cli() {
    set -e
    mysql -h $MYSQL_HOST -P $MYSQL_PORT -u $MYSQL_USER -p${MYSQL_PASSWORD} -D $MYSQL_DB "$@"
    set +e
}

search_expect_fail() {
    local artifact=$1
    rekor-cli --rekor_server $REKOR_ADDRESS search --artifact $artifact 2>/dev/null
    if [ $? -eq 0 ] ; then
        echo "Unexpected index found."
        exit 1
    fi
}

search_expect_success() {
    local artifact=$1
    rekor-cli --rekor_server $REKOR_ADDRESS search --artifact $artifact 2>/dev/null
    if [ $? -ne 0 ] ; then
        echo "Unexpected missing index."
        exit 1
    fi
}
