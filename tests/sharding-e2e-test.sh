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

# Spin up services as usual

echo "Installing createtree..."
go install github.com/google/trillian/cmd/createtree@latest


echo "starting services"
docker-compose up -d
rm ~/.rekor/state.json || true

echo "building CLI and server"
go build -o rekor-cli ./cmd/rekor-cli
REKOR_CLI=$(pwd)/rekor-cli
go build -o rekor-server ./cmd/rekor-server

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

count=0

echo -n "waiting up to 60 sec for system to start"
until [ $(docker-compose ps | grep -c "(healthy)") == 3 ];
do
    if [ $count -eq 6 ]; then
       echo "! timeout reached"
       exit 1
    else
       echo -n "."
       sleep 10
       let 'count+=1'
    fi
done

echo

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
SHARDING_CONFIG=sharding-config.yaml
cat << EOF > $SHARDING_CONFIG
- treeID: $INITIAL_TREE_ID
  treeLength: 3
EOF


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

docker-compose -f $COMPOSE_FILE up  -d
sleep 15
$REKOR_CLI loginfo --rekor_server http://localhost:3000 

# Make sure we are pointing to the new tree now
TREE_ID=$($REKOR_CLI loginfo --rekor_server http://localhost:3000  --format json)
# Check that the SHARD_TREE_ID is a substring of the `$REKOR_CLI loginfo` output
if [[ "$TREE_ID" == *"$SHARD_TREE_ID"* ]]; then
  echo "Rekor server is now pointing to the new shard"
else
  echo "Rekor server is not pointing to the new shard"
  exit 1
fi

# Now, if we run $REKOR_CLI get --log_index 2 again, it should grab the log index
# from Shard 0
check_log_index 2

# Add in a new entry to this shard
pushd tests/sharding-testdata
$REKOR_CLI upload --artifact file2 --signature file2.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
popd
# Pass in the universal log_index & make sure it resolves 
check_log_index 3

# Make sure we can still get logproof for the now-inactive shard
$REKOR_CLI logproof --last-size 2 --tree-id $INITIAL_TREE_ID --rekor_server http://localhost:3000
# And the logproof for the now active shard
$REKOR_CLI logproof --last-size 1 --rekor_server http://localhost:3000

# TODO: Try to get the entry via Entry ID (Tree ID in hex + UUID)
UUID=$($REKOR_CLI get --log-index 2 --rekor_server http://localhost:3000 --format json | jq -r .UUID)

echo "Test passed successfully :)"
