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
MYSQL_HOST=127.0.0.1
MYSQL_PORT=3306
MYSQL_USER=test
MYSQL_PASSWORD=zaphod
MYSQL_DB=test

testdir=$(mktemp -d)

declare -A expected_artifacts
declare -A expected_keys

source $(dirname "$0")/index-test-utils.sh

trap cleanup EXIT

remove_keys() {
    set -e
    for i in $@ ; do
        local rekord=$(rekor-cli --rekor_server $REKOR_ADDRESS get --log-index $i --format json)
        local uuid=$(echo $rekord | jq -r .UUID)
        local sha=sha256:$(echo $rekord | jq -r .Body.RekordObj.data.hash.value)
        local key=$(echo $rekord | jq -r .Body.RekordObj.signature.publicKey.content | base64 -d | sha256sum | cut -d ' ' -f 1)
        if [ "$INDEX_BACKEND" == "redis" ] ; then
            redis_cli LREM $sha 1 $uuid
            redis_cli LREM $key 1 $uuid
        else
            mysql_cli -e "DELETE FROM EntryIndex WHERE EntryUUID = '$uuid'"
        fi
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
        # Check the values of each key for redis so we know there aren't duplicates.
        # We don't need to do this for mysql, we'll just go by the total row count.
        if [ "$INDEX_BACKEND" == "redis" ] ; then
            local actual_length=$(redis_cli LLEN sha256:${sha})
            if [ $expected_length -ne $actual_length ] ; then
                echo "Possible dupicate keys for artifact $artifact."
                exit 1
            fi
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
        # Check the values of each key for redis so we know there aren't duplicates.
        # We don't need to do this for mysql, we'll just go by the total row count.
        if [ "$INDEX_BACKEND" = "redis" ] ; then
            local actual_length=$(redis_cli LLEN $keysha)
            if [ $expected_length -ne $actual_length ] ; then
                echo "Possible dupicate keys for artifact $artifact."
                exit 1
            fi
        fi
    done
    local expected_size
    local actual_size
    if [ "${INDEX_BACKEND}" == "redis" ] ; then
        expected_size=20
        actual_size=$(redis_cli DBSIZE)
    else
        expected_size=26
        actual_size=$(mysql_cli -NB -e "SELECT COUNT(*) FROM EntryIndex;")
    fi
    if [ $expected_size -ne $actual_size ] ; then
        echo "Found unexpected number of index entries: $actual_size."
        exit 1
    fi
    set +e
}

run_backfill() {
    set -e
    local end_index=$1
    if [ "$INDEX_BACKEND" == "redis" ] ; then
        go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
            --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD \
            --concurrency 5 --start 0 --end $end_index
    else
        go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
            --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" \
            --concurrency 5 --start 0 --end $end_index
    fi
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

# delete all keys (including the checkpoints on Redis, but those aren't needed here)
if [ "$INDEX_BACKEND" == "redis" ] ; then
    redis_cli FLUSHALL
else
    mysql_cli -e "DELETE FROM EntryIndex;"
fi

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
