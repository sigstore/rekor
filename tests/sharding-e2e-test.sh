#!/bin/bash
#
# Copyright 2021 The Sigstore Authors.
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

set -ex

# Things to install first:
# - jq, createtree

docker_compose="docker compose"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose"
fi

# Spin up services as usual

echo "Installing createtree..."
go install github.com/google/trillian/cmd/createtree@latest

echo "starting services"
${docker_compose} up -d --build
rm ~/.rekor/state.json || true

echo "building CLI"
go build -o rekor-cli ./cmd/rekor-cli
REKOR_CLI=$(pwd)/rekor-cli

function check_log_index () {
  logIndex=$1
  # make sure we can get this log index from rekor
  $REKOR_CLI get --log-index $logIndex --rekor_server http://localhost:3000
  # make sure the entry index matches the log index
  gotIndex=$($REKOR_CLI get --log-index $logIndex --rekor_server http://localhost:3000 --format json | jq -r .LogIndex)
  if [[ "$gotIndex" == $logIndex ]]; then
    echo "New entry has expected virtual log index $gotIndex"
  else
    echo "FAIL: expected virtual log index $logIndex, got $gotIndex"
    exit 1
  fi
}

function stringsMatch () {
  one=$1
  two=$2

  if [[ "$one" == "$two" ]]; then
    echo "Strings match"
  else
    echo "$one and $two don't match but should"
    exit 1
  fi
}

function stringsNotMatch () {
  one=$1
  two=$2

  if [[ "$one" != "$two" ]]; then
    echo "Strings do not match"
  else
    echo "Strings $one match but shouldn't"
    exit 1
  fi
}

function waitForRekorServer () {
  count=0

  echo -n "waiting up to 60 sec for system to start"
  until [ $(${docker_compose} ps | grep -c "(healthy)") == 3 ];
  do
      if [ $count -eq 6 ]; then
        echo "! timeout reached"
        REKOR_CONTAINER_ID=$(docker ps --filter name=rekor-server --format {{.ID}})
        docker logs $REKOR_CONTAINER_ID
        exit 1
      else
        echo -n "."
        sleep 10
        let 'count+=1'
      fi
  done

  echo
}

function collectLogsOnFailure () {
    if [[ "$1" -ne "0" ]]; then
        echo "failure detected, collecting docker-compose logs"
        ${docker_compose} logs --no-color > /tmp/docker-compose.log
        exit $1
    elif ${docker_compose} logs --no-color | grep -q "panic: runtime error:" ; then
        # if we're here, we found a panic
        echo "failing due to panics detected in logs"
        ${docker_compose} logs --no-color > /tmp/docker-compose.log
        exit 1
    fi
    exit 0
}
trap "collectLogsOnFailure \$?" EXIT

echo "Waiting for rekor server to come up..."
waitForRekorServer

# Add some things to the tlog :)
pushd tests
$REKOR_CLI upload --artifact test_file.txt --signature test_file.sig --public-key test_public_key.key --rekor_server http://localhost:3000
popd

# Make sure we can prove consistency
$REKOR_CLI loginfo --rekor_server http://localhost:3000 

# Add 2 more entries to the log
pushd tests/sharding-testdata
$REKOR_CLI upload --artifact file1 --signature file1.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
$REKOR_CLI upload --artifact file2 --signature file2.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
popd


INITIAL_TREE_ID=$($REKOR_CLI loginfo --rekor_server http://localhost:3000  --format json  | jq -r .TreeID)
echo "Initial Tree ID is $INITIAL_TREE_ID"

# Make sure we have three entries in the log
check_log_index 2
$REKOR_CLI logproof --rekor_server http://localhost:3000 --last-size 2

# Now, we want to shard the log.
# Create a new tree
echo "creating a new Tree ID...."
SHARD_TREE_ID=$(createtree --admin_server localhost:8090)
echo "the new shard ID is $SHARD_TREE_ID"

# Once more
$REKOR_CLI loginfo --rekor_server http://localhost:3000

# Spin down the rekor server
echo "stopping the rekor server..."
REKOR_CONTAINER_ID=$(docker ps --filter name=rekor-server --format {{.ID}})
docker stop $REKOR_CONTAINER_ID

# Now we want to spin up the Rekor server again, but this time point
# to the new tree
# New shard will have a different signing key.
SHARDING_CONFIG=sharding-config.yaml
cat << EOF > $SHARDING_CONFIG
- treeID: $INITIAL_TREE_ID
  signingConfig:
    signingSchemeOrKeyPath: memory
EOF

cat $SHARDING_CONFIG

COMPOSE_FILE=docker-compose-sharding.yaml
cat << EOF > $COMPOSE_FILE
version: '3.4'
services:
  rekor-server:
    build:
      context: .
      target: "deploy"
    command: [
      "rekor-server",
      "serve",
      "--trillian_log_server.address=trillian-log-server",
      "--trillian_log_server.port=8090",
      "--redis_server.address=redis-server",
      "--redis_server.port=6379",
      "--rekor_server.address=0.0.0.0",
      "--rekor_server.signer=memory",
      "--enable_attestation_storage",
      "--attestation_storage_bucket=file:///var/run/attestations",
      "--trillian_log_server.tlog_id=$SHARD_TREE_ID",
      "--trillian_log_server.sharding_config=/$SHARDING_CONFIG"
      # Uncomment this for production logging
      # "--log_type=prod",
      ]
    volumes:
    - "/var/run/attestations:/var/run/attestations:z"
    - "./$SHARDING_CONFIG:/$SHARDING_CONFIG:z"
    restart: always # keep the server running
    ports:
      - "3000:3000"
      - "2112:2112"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/ping"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
EOF

# Spin up the new Rekor

${docker_compose} -f $COMPOSE_FILE up -d
waitForRekorServer
$REKOR_CLI loginfo --rekor_server http://localhost:3000 

# Make sure we are pointing to the new tree now
TREE_ID=$($REKOR_CLI loginfo --rekor_server http://localhost:3000  --format json | jq -r .TreeID)
# Check that the SHARD_TREE_ID is a substring of the `$REKOR_CLI loginfo` output
stringsMatch $TREE_ID $SHARD_TREE_ID

# Now, if we run $REKOR_CLI get --log_index 2 again, it should grab the log index
# from Shard 0
check_log_index 2

# Add in a new entry to this shard
pushd tests/sharding-testdata
$REKOR_CLI upload --artifact file2 --signature file2.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
popd
# Pass in the universal log_index & make sure it resolves 
check_log_index 3

# Make sure the shard tree size is 1 and the total tree size is 4
rm $HOME/.rekor/state.json # We have to remove this since we can't prove consistency between entry 0 and entry 1
TREE_SIZE=$($REKOR_CLI loginfo --rekor_server http://localhost:3000 --format json | jq -r .ActiveTreeSize)
stringsMatch $TREE_SIZE "1"

TOTAL_TREE_SIZE=$($REKOR_CLI loginfo --rekor_server http://localhost:3000 --format json | jq -r .TotalTreeSize)
stringsMatch $TOTAL_TREE_SIZE "4"


# Make sure we can still get logproof for the now-inactive shard
$REKOR_CLI logproof --last-size 2 --tree-id $INITIAL_TREE_ID --rekor_server http://localhost:3000
# And the logproof for the now active shard
$REKOR_CLI logproof --last-size 1 --rekor_server http://localhost:3000

# Make sure the shard keys are different
echo "Getting public key for inactive shard..."
INACTIVE_PUB_KEY=$(curl "http://localhost:3000/api/v1/log/publicKey?treeID=$INITIAL_TREE_ID" | base64 -w 0)
echo "Getting the public key for the active tree..."
NEW_PUB_KEY=$(curl "http://localhost:3000/api/v1/log/publicKey" | base64 -w 0)
echo "Making sure the public key for the active shard is different from the inactive shard..."
if [[ "$INACTIVE_PUB_KEY" == "$NEW_PUB_KEY" ]]; then
    echo
    echo "Active tree public key should be different from inactive shard public key but isn't..."
    echo "Inactive Shard Public Key: $INACTIVE_PUB_KEY"
    echo "Active Shard Public Key: $NEW_PUB_KEY"
    exit 1
fi

# TODO: Try to get the entry via Entry ID (Tree ID in hex + UUID)
echo
echo "Testing /api/v1/log/entries/retrieve endpoint..."

ENTRY_ID_1=$($REKOR_CLI get --log-index 1 --rekor_server http://localhost:3000 --format json | jq -r .UUID)
ENTRY_ID_2=$($REKOR_CLI get --log-index 3 --rekor_server http://localhost:3000 --format json | jq -r .UUID)


# Make sure retrieve by UUID in the inactive shard works
NUM_ELEMENTS=$(curl -f http://localhost:3000/api/v1/log/entries/retrieve -H "Content-Type: application/json" -H "Accept: application/json" -d "{ \"entryUUIDs\": [\"$ENTRY_ID_1\"]}" | jq '. | length')
stringsMatch $NUM_ELEMENTS "1"

# Make sure we can verify the entry we entered into the now-inactive shard
pushd tests
$REKOR_CLI verify --artifact test_file.txt --signature test_file.sig --public-key test_public_key.key --rekor_server http://localhost:3000
popd

# -f makes sure we exit on failure
NUM_ELEMENTS=$(curl -f http://localhost:3000/api/v1/log/entries/retrieve -H "Content-Type: application/json" -H "Accept: application/json" -d "{ \"entryUUIDs\": [\"$ENTRY_ID_1\", \"$ENTRY_ID_2\"]}" | jq '. | length')
stringsMatch $NUM_ELEMENTS "2"

# Make sure the /api/v1/log/entries/retrieve endpoint is resolving virtual indexes correctly
NUM_ELEMENTS=$(curl -f -H "Content-Type: application/json" --data '{"logIndexes": [0,3]}'  "http://localhost:3000/api/v1/log/entries/retrieve" | jq '. | length')
stringsMatch $NUM_ELEMENTS "2"

# Make sure we get the expected LogIndex in the response when calling /retrieve endpoint
RETRIEVE_LOGINDEX1=$(curl -f http://localhost:3000/api/v1/log/entries/retrieve -H "Content-Type: application/json" -H "Accept: application/json" -d "{ \"logIndexes\": [1]}" | jq '.[0]' | jq -r "with_entries(select(.key|test(\"^"$ENTRY_ID_1"$\"))) | .[].logIndex")
stringsMatch $RETRIEVE_LOGINDEX1 "1"

# Make sure that verification succeeds via UUID
echo
echo "Testing rekor-cli verification via UUID..."
$REKOR_CLI verify --uuid $ENTRY_ID_1 --rekor_server http://localhost:3000

# Make sure that verification succeeds via Entry ID (Tree ID in hex + UUID)
echo
echo "Testing rekor-cli verification via Entry ID..."
DEBUG=1 $REKOR_CLI verify --uuid $ENTRY_ID_1 --rekor_server http://localhost:3000

# Verify that the checkpoint/SignedTreeHead for inactive shards is cached between calls
ACTIVE_SHARD_CHECKPOINT=$(curl "http://localhost:3000/api/v1/log" | jq .signedTreeHead | base64 -w 0)
INACTIVE_SHARD_CHECKPOINT=$(curl "http://localhost:3000/api/v1/log" | jq .inactiveShards[0].signedTreeHead | base64 -w 0)
ACTIVE_SHARD_CHECKPOINT_NOT_CACHED=$(curl "http://localhost:3000/api/v1/log" | jq .signedTreeHead | base64 -w 0)
INACTIVE_SHARD_CHECKPOINT_CACHED=$(curl "http://localhost:3000/api/v1/log" | jq .inactiveShards[0].signedTreeHead | base64 -w 0)
# inactive shard checkpoint is cached
stringsMatch $INACTIVE_SHARD_CHECKPOINT $INACTIVE_SHARD_CHECKPOINT_CACHED
# active shard checkpoint is not cached
stringsNotMatch $ACTIVE_SHARD_CHECKPOINT $ACTIVE_SHARD_CHECKPOINT_NOT_CACHED

echo "Test passed successfully :)"
