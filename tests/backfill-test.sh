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

REKOR_ADDRESS=http://localhost:3000
REDIS_HOST=localhost
REDIS_PORT=6379
REDIS_PASSWORD=test

testdir=$(mktemp -d)

declare -A expected_artifacts
declare -A expected_keys

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
        docker-compose -f docker-compose.yml -f docker-compose.backfill-test.yml logs --no-color > /tmp/docker-compose.log
    fi
    docker-compose down --remove-orphans
    rm -rf $testdir
    exit $rv
}
trap cleanup EXIT

docker_up () {
    set -e
    docker-compose -f docker-compose.yml -f docker-compose.backfill-test.yml up -d --build
    local count=0
    echo "waiting up to 2 min for system to start"
    until [ $(docker-compose ps | \
       grep -E "(rekor[-_]mysql|rekor[-_]redis|rekor[-_]rekor-server)" | \
       grep -c "(healthy)" ) == 3 ];
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

remove_keys() {
    set -e
    for i in $@ ; do
        local rekord=$(rekor-cli --rekor_server $REKOR_ADDRESS get --log-index $i --format json)
        local uuid=$(echo $rekord | jq -r .UUID)
        local sha=sha256:$(echo $rekord | jq -r .Body.RekordObj.data.hash.value)
        local key=$(echo $rekord | jq -r .Body.RekordObj.signature.publicKey.content | base64 -d | sha256sum | cut -d ' ' -f 1)
        redis_cli LREM $sha 1 $uuid
        redis_cli LREM $key 1 $uuid
    done
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

check_all_entries() {
    set -e
    for artifact in "${!expected_artifacts[@]}" ; do
        local expected_uuids="${expected_artifacts[$artifact]}"
        local sha=$(sha256sum $artifact | cut -d ' ' -f 1)
        local actual_uuids=$(rekor-cli --rekor_server $REKOR_ADDRESS search --sha $sha --format json | jq -r .UUIDs[])
        for au in $actual_uuids ; do
            local found=0
            for eu in $expected_uuids ; do
                if [ "$au" == "$eu" ] ; then
                    found=1
                    break
                fi
            done
            if [ $found -eq 0 ] ; then
                echo "Backfill did not add expected artifact $artifact."
                exit 1
            fi
        done
        expected_uuids=($expected_uuids)
        local expected_length=${#expected_uuids[@]}
        local actual_length=$(redis_cli LLEN sha256:${sha})
        if [ $expected_length -ne $actual_length ] ; then
            echo "Possible dupicate keys for artifact $artifact."
            exit 1
        fi
    done
    for key in "${!expected_keys[@]}" ; do
        expected_uuids=${expected_keys[$key]}
        actual_uuids=$(rekor-cli --rekor_server $REKOR_ADDRESS search --pki-format minisign --public-key $key --format json | jq -r .UUIDs[])
        for au in $actual_uuids ; do
            local found=0
            for eu in $expected_uuids ; do
                if [ "$au" == "$eu" ] ; then
                    found=1
                    break
                fi
            done
            if [ $found -eq 0 ] ; then
                echo "Backfill did not add expected key $key."
                exit 1
            fi
        done
        local keysha=$(echo -n $(tail -1 $key) | sha256sum | cut -d ' ' -f 1)
        expected_uuids=($expected_uuids)
        local expected_length=${#expected_uuids[@]}
        local actual_length=$(redis_cli LLEN $keysha)
        if [ $expected_length -ne $actual_length ] ; then
            echo "Possible dupicate keys for artifact $artifact."
            exit 1
        fi
    done
    local dbsize=$(redis_cli DBSIZE)
    if [ $dbsize -ne 20 ] ; then
        echo "Found unexpected number of index entries: $dbsize."
        exit 1
    fi
    set +e
}

run_backfill() {
    set -e
    local end_index=$1
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD \
        --concurrency 5 --start 0 --end $end_index
    set +e
}

docker_up

make_entries

set -e
loginfo=$(rekor-cli --rekor_server $REKOR_ADDRESS loginfo --format=json)
let end_index=$(echo $loginfo | jq .ActiveTreeSize)-1
set +e

echo
echo "##### Scenario 1: backfill from scratch #####"
echo

# delete all keys (including the checkpoints, but those aren't needed here)
redis_cli FLUSHALL

# searching for any artifact should fail
search_expect_fail $testdir/blob1

run_backfill $end_index

check_all_entries

echo "Scenario 1: SUCCESS"

echo
echo "##### Scenario 2: backfill last half of entries #####"
echo

remove_keys $(seq 6 12)

# searching for artifact 0-5 should succeed, but searching for later artifacts should fail
search_expect_success $testdir/blob1
search_expect_fail $testdir/blob9

run_backfill $end_index

check_all_entries

echo "Scenario 2: SUCCESS"

echo
echo "##### Scenario 3: backfill sparse entries #####"
echo

remove_keys $(seq 2 2 12)

# searching for odd artifacts should succeed, but searching for even artifacts should fail unless it was re-signed
search_expect_success $testdir/blob5
search_expect_fail $testdir/blob2
search_expect_success $testdir/blob8

run_backfill $end_index

check_all_entries

echo "Scenario 3: SUCCESS"

echo
echo "##### Scenario 4: backfill full instance (noop) #####"
echo

run_backfill $end_index

check_all_entries

echo "Scenario 4: SUCCESS"
