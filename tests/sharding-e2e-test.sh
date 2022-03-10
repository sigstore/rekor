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

# rekor-cli loginfo should work
$REKOR_CLI loginfo --rekor_server http://localhost:3000 --store_tree_state=false
CURRENT_TREE_ID=$($REKOR_CLI loginfo --rekor_server http://localhost:3000  --format json --store_tree_state=false | jq -r .TreeID)
echo "current Tree ID is $CURRENT_TREE_ID"


# Add some things to the tlog :)
cd tests
$REKOR_CLI upload --artifact test_file.txt --signature test_file.sig --public-key test_public_key.key --rekor_server http://localhost:3000
cd sharding-testdata
$REKOR_CLI upload --artifact file1 --signature file1.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
$REKOR_CLI upload --artifact file2 --signature file2.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
cd ../..

# Make sure we have three entries in the log
$REKOR_CLI get --log-index 2 --rekor_server http://localhost:3000

# Now, we want to shard the log.
# Create a new tree
echo "creating a new Tree ID...."
SHARD_TREE_ID=$(createtree --admin_server localhost:8090)
echo "the new shard ID is $SHARD_TREE_ID"

# Once more
$REKOR_CLI loginfo --rekor_server http://localhost:3000 --store_tree_state=false

# Spin down the rekor server
echo "stopping the rekor server..."
REKOR_CONTAINER_ID=$(docker ps --filter name=rekor-server --format {{.ID}})
docker stop $REKOR_CONTAINER_ID


# Now we want to spin up the Rekor server again, but this time point
# to the new tree

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
      "--trillian_log_server.log_id_ranges=$CURRENT_TREE_ID=3,$SHARD_TREE_ID"
      # Uncomment this for production logging
      # "--log_type=prod",
      ]
    volumes:
    - "/var/run/attestations:/var/run/attestations:z"
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
# TODO: priyawadhwa@ remove --store_tree_state=false once $REKOR_CLI loginfo is aware of shards
$REKOR_CLI loginfo --rekor_server http://localhost:3000 --store_tree_state=false

# Make sure we are pointing to the new tree now
TREE_ID=$($REKOR_CLI loginfo --rekor_server http://localhost:3000  --format json --store_tree_state=false)
# Check that the SHARD_TREE_ID is a substring of the `$REKOR_CLI loginfo` output
if [[ "$TREE_ID" == *"$SHARD_TREE_ID"* ]]; then
  echo "Rekor server is now pointing to the new shard"
else
  echo "Rekor server is not pointing to the new shard"
  exit 1
fi

# Now, if we run $REKOR_CLI get --log_index 2 again, it should grab the log index
# from Shard 0
$REKOR_CLI get --log-index 2 --rekor_server http://localhost:3000

# Add in a new entry to this shard
pushd tests/sharding-testdata
$REKOR_CLI upload --artifact file2 --signature file2.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000
popd
# Pass in the universal log_index & make sure it resolves 
$REKOR_CLI get --log-index 3 --rekor_server http://localhost:3000

# Get the virtual log index, which should be universal. Since we have four entries across two shards, the virtual index is 3.
VIRTUAL_INDEX=$($REKOR_CLI get --log-index 3 --rekor_server http://localhost:3000 --format json | jq -r .LogIndex)
if [[ "$VIRTUAL_INDEX" == "3" ]]; then
  echo "New entry has expected virtual log index $VIRTUAL_INDEX"
else
  echo "New entry does not have expected virtual log index, index instead is $VIRTUAL_INDEX"
  exit 1
fi

# TODO: Try to get the entry via Entry ID (Tree ID in hex + UUID)
UUID=$($REKOR_CLI get --log-index 2 --rekor_server http://localhost:3000 --format json | jq -r .UUID)

echo "Test passed successfully :)"
