#!/usr/bin/env bash
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

set -e
testdir=$(dirname "$0")

docker_compose="docker compose -f docker-compose.yml -f docker-compose.test.yml"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose -f docker-compose.yml -f docker-compose.test.yml"
fi

rm -f /tmp/rekor-*.cov

echo "installing gocovmerge"
make gocovmerge

echo "building test-only containers"
docker build -t gcp-pubsub-emulator -f Dockerfile.pubsub-emulator .

echo "starting services"
${docker_compose} up -d --build

echo "building CLI and server"
go test -c ./cmd/rekor-cli -o rekor-cli -cover -covermode=count -coverpkg=./...
go test -c ./cmd/rekor-server -o rekor-server -covermode=count -coverpkg=./...

count=0

echo "waiting up to 2 min for system to start"
until [ $(${docker_compose} ps | \
   grep -E "(rekor[-_]mysql|rekor[-_]rekor-server|rekor[-_]gcp-pubsub-emulator)" | \
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

echo
echo "running tests"
REKORTMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
touch $REKORTMPDIR.rekor.yaml
trap "rm -rf $REKORTMPDIR" EXIT
if ! REKORTMPDIR=$REKORTMPDIR go test -tags=e2e ./tests/ -run TestIssue1308; then
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
fi
if ! REKORTMPDIR=$REKORTMPDIR PUBSUB_EMULATOR_HOST=localhost:8085 go test -tags=e2e ./tests/; then 
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
fi
if ${docker_compose} logs --no-color | grep -q "panic: runtime error:" ; then
   # if we're here, we found a panic
   echo "Failing due to panics detected in logs"
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
fi

echo "generating code coverage"
${docker_compose} restart rekor-server

if ! docker cp $(docker ps -aqf "name=rekor_rekor-server" -f "name=rekor-rekor-server"):/go/rekor-server.cov /tmp/rekor-server.cov ; then
   # failed to copy code coverage report from server
   echo "Failed to retrieve server code coverage report"
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
fi

# merging coverage reports and filtering out /pkg/generated from final report
hack/tools/bin/gocovmerge /tmp/rekor-*.cov | grep -v "/pkg/generated/" > /tmp/rekor-merged.cov
echo "code coverage $(go tool cover -func=/tmp/rekor-merged.cov | grep -E '^total\:' | sed -E 's/\s+/ /g')"
