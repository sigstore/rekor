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

clear_checkpoint() {
    local checkpoint_key=${1:-default}
    if [ "$INDEX_BACKEND" == "redis" ] ; then
        redis_cli DEL "backfill/checkpoint/$checkpoint_key" 2>/dev/null || true
    else
        mysql_cli -e "DELETE FROM BackfillCheckpoint WHERE CheckpointKey='$checkpoint_key';" 2>/dev/null || true
    fi
}

check_all_entries() {
    local expected_redis=${1:-21}  # 20 index keys + 1 checkpoint key
    local expected_mysql=${2:-26}
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
        expected_size=$expected_redis
        actual_size=$(redis_cli DBSIZE)
    else
        expected_size=$expected_mysql
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

# Clear checkpoint since we're modifying the index
clear_checkpoint

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

# Clear checkpoint since we're modifying the index
clear_checkpoint

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

echo
echo "##### Scenario 5: checkpoint and resume #####"
echo

# Start fresh, make sure we have a clean index
if [ "$INDEX_BACKEND" == "redis" ] ; then
    redis_cli FLUSHALL
else
    mysql_cli -e "DELETE FROM EntryIndex; DELETE FROM BackfillCheckpoint;" 2>/dev/null || true
fi

echo "Initial backfill from 0 to $end_index with checkpointing"
set -e
if [ "$INDEX_BACKEND" == "redis" ] ; then
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD \
        --concurrency 5 --start 0 --end $end_index \
        --checkpoint-interval 2
else
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" \
        --concurrency 5 --start 0 --end $end_index \
        --checkpoint-interval 2
fi
set +e

# Capture initial checkpoint value for later
initial_checkpoint=$end_index

echo "Adding more entries to the log..."
for i in $(seq 13 20) ; do
    minisign -GW -p $testdir/mini${i}.pub -s $testdir/mini${i}.key
    echo test${i} > $testdir/blob${i}
    minisign -S -s $testdir/mini${i}.key -m $testdir/blob${i}
    rekor_out=$(rekor-cli --rekor_server $REKOR_ADDRESS upload \
        --artifact $testdir/blob${i} \
        --pki-format=minisign \
        --public-key $testdir/mini${i}.pub \
        --signature $testdir/blob${i}.minisig \
        --format json)
    uuid=$(echo $rekor_out | jq -r .Location | cut -d '/' -f 6)
    expected_keys["$testdir/mini${i}.pub"]=$uuid
    expected_artifacts["$testdir/blob${i}"]=$uuid
done

set -e
loginfo=$(rekor-cli --rekor_server $REKOR_ADDRESS loginfo --format=json)
let new_end_index=$(echo $loginfo | jq .ActiveTreeSize)-1
set +e

echo "New entries added, log now has indices 0-$new_end_index"

echo "Running backfill from 0 to $new_end_index (should resume from checkpoint)"
if [ "$INDEX_BACKEND" == "redis" ] ; then
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD \
        --concurrency 5 --start 0 --end $new_end_index \
        --checkpoint-interval 2 2>&1 | tee /tmp/backfill-resume.log
else
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" \
        --concurrency 5 --start 0 --end $new_end_index \
        --checkpoint-interval 2 2>&1 | tee /tmp/backfill-resume.log
fi

if ! grep -q "Resuming from checkpoint: last completed index $initial_checkpoint" /tmp/backfill-resume.log ; then
    echo "Scenario 5: FAILED - Did not resume from checkpoint"
    cat /tmp/backfill-resume.log
    exit 1
fi
echo "Verified: Backfill resumed from checkpoint index $initial_checkpoint"

# Verify all entries are indexed and checkpoint is at the end
# After adding 8 new entries (13-20), total is 21 entries:
#   Redis: 20 index + 16 new index + 1 checkpoint = 37 keys
#   MySQL: 26 + (8 entries × 2 rows) = 42 rows
check_all_entries 37 42

if [ "$INDEX_BACKEND" == "redis" ] ; then
    checkpoint_data=$(redis_cli GET "backfill/checkpoint/default")
    final_checkpoint=$(echo $checkpoint_data | jq -r .last_completed_index)
else
    final_checkpoint=$(mysql_cli -NB -e "SELECT LastCompletedIndex FROM BackfillCheckpoint WHERE CheckpointKey='default'")
fi

if [ "$final_checkpoint" != "$new_end_index" ] ; then
    echo "Scenario 5: FAILED - Checkpoint should be at end index $new_end_index, got $final_checkpoint"
    exit 1
fi
echo "Checkpoint at index $final_checkpoint (end of log)"

echo "Testing --reset-checkpoint flag"
reset_end_index=5
if [ "$INDEX_BACKEND" == "redis" ] ; then
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --redis-hostname $REDIS_HOST --redis-port $REDIS_PORT --redis-password $REDIS_PASSWORD \
        --concurrency 5 --start 0 --end $reset_end_index \
        --checkpoint-interval 2 --reset-checkpoint 2>&1 | tee /tmp/backfill-reset.log
else
    go run cmd/backfill-index/main.go --rekor-address $REKOR_ADDRESS \
        --mysql-dsn "${MYSQL_USER}:${MYSQL_PASSWORD}@tcp(${MYSQL_HOST}:${MYSQL_PORT})/${MYSQL_DB}" \
        --concurrency 5 --start 0 --end $reset_end_index \
        --checkpoint-interval 2 --reset-checkpoint 2>&1 | tee /tmp/backfill-reset.log
fi

if grep -q "Resuming from checkpoint" /tmp/backfill-reset.log ; then
    echo "Scenario 5: FAILED - Reset flag did not clear checkpoint"
    exit 1
fi
if ! grep -q "Checkpoint reset - starting fresh" /tmp/backfill-reset.log ; then
    echo "Scenario 5: FAILED - Did not see checkpoint reset message"
    exit 1
fi

if [ "$INDEX_BACKEND" == "redis" ] ; then
    checkpoint_data=$(redis_cli GET "backfill/checkpoint/default")
    reset_checkpoint=$(echo $checkpoint_data | jq -r .last_completed_index)
else
    reset_checkpoint=$(mysql_cli -NB -e "SELECT LastCompletedIndex FROM BackfillCheckpoint WHERE CheckpointKey='default'")
fi

if [ "$reset_checkpoint" != "$reset_end_index" ] ; then
    echo "Scenario 5: FAILED - Checkpoint should be at end index $reset_end_index, got $reset_checkpoint"
    exit 1
fi
echo "Checkpoint reset and at index $reset_checkpoint (end of range)"

check_all_entries 37 42

echo "Scenario 5: SUCCESS"
