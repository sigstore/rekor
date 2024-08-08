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

make_intoto_entries() {
    set -e
    for type in intoto:0.0.1 intoto:0.0.2 dsse ; do
        rekor-cli --rekor_server $REKOR_ADDRESS upload \
            --type $type \
            --artifact tests/intoto_dsse.json \
            --public-key tests/intoto_dsse.pem \
            --format=json
    done
    set +e
}

search_sha_expect_success() {
    local sha=$1
    rekor-cli --rekor_server $REKOR_ADDRESS search --sha $sha 2>/dev/null
    if [ $? -ne 0 ] ; then
        echo "Unexpected missing index."
        exit 1
    fi
}

check_basic_entries() {
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
    set +e
}

check_intoto_entries() {
    local dsse_sha=$(sha256sum tests/intoto_dsse.json | cut -d ' ' -f 1)
    local dsse_key_sha=$(echo | cat tests/intoto_dsse.pem - | sha256sum | cut -d ' ' -f 1)
    local dsse_payload=$(jq -r .payload tests/intoto_dsse.json | base64 -d | sha256sum)

    search_expect_success tests/intoto_dsse.json
    search_sha_expect_success $dsse_sha
    search_sha_expect_success $dsse_key_sha
    search_sha_expect_success $dsse_payload
}

run_copy() {
    set -e
    go run cmd/copy-index/main.go \
        --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" \
        --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD \
        --batch-size 5
    set +e
}

export INDEX_BACKEND=redis
docker_up

make_entries
make_intoto_entries

check_basic_entries
check_intoto_entries

export INDEX_BACKEND=mysql
docker-compose stop rekor-server
docker_up

search_expect_fail tests/intoto_dsse.json # the new index backend should be empty at this point

run_copy

check_basic_entries
check_intoto_entries
