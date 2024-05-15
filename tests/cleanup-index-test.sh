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

source $(dirname "$0")/index-test-utils.sh

trap cleanup EXIT

make_entries() {
    set -e
    # make 10 unique artifacts and sign each once
    for i in $(seq 0 9) ; do
        minisign -GW -p $testdir/mini${i}.pub -s $testdir/mini${i}.key
        echo test${i} > $testdir/blob${i}
        minisign -S -s $testdir/mini${i}.key -m $testdir/blob${i}
        rekor-cli --rekor_server $REKOR_ADDRESS upload \
            --artifact $testdir/blob${i} \
            --pki-format=minisign \
            --public-key $testdir/mini${i}.pub \
            --signature $testdir/blob${i}.minisig \
            --format json
    done
    # double-sign a few artifacts
    for i in $(seq 7 9) ; do
        set +e
        let key_index=$i-5
        set -e
        minisign -S -s $testdir/mini${key_index}.key -m $testdir/blob${i}
        rekor-cli --rekor_server $REKOR_ADDRESS upload \
            --artifact $testdir/blob${i} \
            --pki-format=minisign \
            --public-key $testdir/mini${key_index}.pub \
            --signature $testdir/blob${i}.minisig \
            --format json
    done
    set +e
}

docker_up

checkpoints=$(redis_cli --scan)

make_entries

set -e
loginfo=$(rekor-cli --rekor_server $REKOR_ADDRESS loginfo --format=json)
let end_index=$(echo $loginfo | jq .ActiveTreeSize)-1
set +e

# check that the entries are in redis
if [ $(redis_cli --scan | grep -v '/' | wc -l) -ne 20 ] ; then
    echo "Setup failed: redis had an unexpected number of index keys."
    exit 1
fi

# backfill to mysql - this isn't useful in a real scenario because
# search_index.storage_provider still points to redis, but it's useful
# to test that the key cleanup is working
go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
    --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" \
    --concurrency 5 --start 0 --end $end_index

# run the cleanup script
go run cmd/cleanup-index/main.go --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD

# there should be no more index entries in redis
if [ $(redis_cli --scan | grep -v '/' | wc -l) -ne 0 ] ; then
    echo "Found index keys remaining in redis."
    exit 1
fi

# the checkpoints should have been left alone
for cp in $checkpoints ; do
    if [ $(redis_cli EXISTS $cp) -ne 1 ] ; then
        echo "Missing checkpoint $cp"
        exit 1
    fi
done
