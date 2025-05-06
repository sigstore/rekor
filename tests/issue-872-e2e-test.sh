#!/bin/bash
#
# Copyright 2022 The Sigstore Authors.
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

set -e
testdir=$(dirname "$0")

docker_compose="docker compose"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose"
fi

echo "* starting services"
${docker_compose} up -d

echo "* building CLI"
go build -o rekor-cli ./cmd/rekor-cli
REKOR_CLI=$(pwd)/rekor-cli

function waitForRekorServer () {
  echo -n "* waiting up to 60 sec for system to start"
  count=0

  until [ $(docker ps -a | grep -c "(healthy)") == 5 ];
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
}

REKORTMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
touch $REKORTMPDIR.rekor.yaml
trap "rm -rf $REKORTMPDIR" EXIT

waitForRekorServer

echo "* stopping rekor to test issue #872"
${docker_compose} stop rekor-server

docker volume rm -f issue872_attestations || true
ATT_VOLUME=$(docker volume create --name issue872_attestations)
# set permissions on docker volume to be friendly to non-root since v0.6.0 container is based on distroless
docker run --rm -v $ATT_VOLUME:/att:z busybox /bin/sh -c 'touch /att/.initialized && chown -R 65532:65532 /att && chmod 777 /att'

V060_COMPOSE_FILE=$REKORTMPDIR/docker-compose-issue872-v060.yaml
cat << EOF > $V060_COMPOSE_FILE
services:
  rekor-server-issue-872-v060:
    # this container image is built on v0.6.0 with the fix for issue #800
    image: gcr.io/projectsigstore/rekor/ci/rekor/rekor-server@sha256:568aee99574e6d796d70b7b1fd59438bd54b3b9f44cc2c9a086629597c66d324
    user: "65532:65532"
    command: [
      "serve",
      "--trillian_log_server.address=trillian-log-server",
      "--trillian_log_server.port=8090",
      "--redis_server.address=redis-server",
      "--redis_server.port=6379",
      "--rekor_server.address=0.0.0.0",
      "--rekor_server.signer=memory",
      "--enable_attestation_storage",
      "--attestation_storage_bucket=file:///ko-app/attestations",
      # Uncomment this for production logging
      # "--log_type=prod",
      ]
    volumes:
    - "$ATT_VOLUME:/ko-app/attestations:z"
    restart: always # keep the server running
    ports:
      - "0.0.0.0:3000:3000"
      - "0.0.0.0:2112:2112"
volumes:
  $ATT_VOLUME:
    external: true
EOF

echo "* starting rekor v0.6.0 to test issue #872"
${docker_compose} -f $V060_COMPOSE_FILE --project-directory=$PWD up -d rekor-server-issue-872-v060
sleep 5

# this rekor-cli image is based on v0.6.0 and has the fix for issue #800
ISSUE800_CONTAINER=gcr.io/projectsigstore/rekor/ci/rekor/rekor-cli@sha256:34f6ec6324a6f32f118dc14d33e5cc081fb8b49a5026d388f782a3566afa2ca8
ISSUE800_CONTAINER_ID=$(docker create $ISSUE800_CONTAINER)
ISSUE800_CLI=$REKORTMPDIR/rekor-cli-issue-800
docker cp "$ISSUE800_CONTAINER_ID:/ko-app/rekor-cli" $ISSUE800_CLI
docker rm $ISSUE800_CONTAINER_ID >/dev/null

V060_UPLOAD_OUTPUT=$REKORTMPDIR/issue-872-upload-output
echo "* inserting intoto entry into Rekor v0.6.0"
if ! $ISSUE800_CLI upload --type intoto --artifact tests/intoto_dsse.json --public-key tests/intoto_dsse.pem --format=json --rekor_server=http://localhost:3000 > $V060_UPLOAD_OUTPUT; then
   echo "* failed to insert intoto entry to test issue #872, exiting"
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   ${docker_compose} -f $V060_COMPOSE_FILE --project-directory=$PWD logs rekor-server-issue-872-v060 > /tmp/post-insert-docker-compose.log
   exit 1
fi

ISSUE872_UPLOAD_INDEX=$(jq -r .Index $V060_UPLOAD_OUTPUT)
V060_GET_OUTPUT=$REKORTMPDIR/issue-872-get-output
echo "* read back entry from Rekor v0.6.0"
if ! $ISSUE800_CLI get --log-index=$ISSUE872_UPLOAD_INDEX  --format=json --rekor_server=http://localhost:3000 > $V060_GET_OUTPUT; then
   echo "* failed to retrieve entry from rekor v0.6.0 to test issue #872, exiting"
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   ${docker_compose} -f $V060_COMPOSE_FILE --project-directory=$PWD logs rekor-server-issue-872-v060 > /tmp/post-insert-docker-compose.log
   exit 1
fi

echo "* checking to ensure attestation is successfully returned from rekor v0.6.0"
V060_ATT_LENGTH=$(jq -r '.Attestation | length' $V060_GET_OUTPUT)
if [ $V060_ATT_LENGTH -eq 0 ]; then
   echo "* failed to read back attestation while testing issue #872 against rekor v0.6.0, exiting"
   cat $V060_GET_OUTPUT
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   ${docker_compose} -f $V060_COMPOSE_FILE --project-directory=$PWD logs rekor-server-issue-872-v060 > /tmp/post-insert-docker-compose.log
   exit 1
fi

echo "* grabbing TreeID to use when starting older version"
REKOR_TRILLIAN_LOG_SERVER_TLOG_ID=$($ISSUE800_CLI loginfo --rekor_server=http://localhost:3000 --format=json | jq -r .TreeID)
echo "* stopping rekor v0.6.0 to test issue #872"
${docker_compose} -f $V060_COMPOSE_FILE --project-directory=$PWD logs rekor-server-issue-872-v060 > /tmp/post-insert-docker-compose.log
${docker_compose} -f $V060_COMPOSE_FILE --project-directory=$PWD stop rekor-server-issue-872-v060

COMPOSE_FILE=$REKORTMPDIR/docker-compose-issue872.yaml
cat << EOF > $COMPOSE_FILE
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
      "--trillian_log_server.tlog_id=$REKOR_TRILLIAN_LOG_SERVER_TLOG_ID",
      # Uncomment this for production logging
      # "--log_type=prod",
      ]
    volumes:
    - "$ATT_VOLUME:/var/run/attestations:z"
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
volumes:
  $ATT_VOLUME:
    external: true
EOF

docker network prune -f
echo "* starting rekor under test to ensure attestation inserted in old version is successfully returned"
${docker_compose} -f $COMPOSE_FILE --project-directory=$PWD up -d
waitForRekorServer

ISSUE872_GET_ENTRY=$REKORTMPDIR/issue-872-get-entry
echo "* fetching previous entry made under v0.6.0"
if ! $REKOR_CLI get --log-index=$ISSUE872_UPLOAD_INDEX --rekor_server=http://localhost:3000 --format=json > $ISSUE872_GET_ENTRY; then
   echo "* failed to read back intoto entry while testing issue #872, exiting"
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
fi

#ensure attestation of len() > 0 returned
echo "* checking to ensure attestation is successfully returned"
ATT_LENGTH=$(jq -r '.Attestation | length' $ISSUE872_GET_ENTRY)
if [ $ATT_LENGTH -eq 0 ]; then
   echo "* failed to read back attestation while testing issue #872, exiting"
   cat $ISSUE872_GET_ENTRY
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
else
   echo "* tests succeeded!"
fi
