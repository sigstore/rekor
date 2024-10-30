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

docker_compose="docker compose -f docker-compose.yml -f docker-compose.test.yml"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose -f docker-compose.yml -f docker-compose.test.yml"
fi

rm -f /tmp/pkg-rekor-*.cov
echo "installing gocovmerge"
make gocovmerge

echo "building test-only containers"
docker build -t gcp-pubsub-emulator -f Dockerfile.pubsub-emulator .
docker kill $(docker ps -q) || true

echo "starting services"
${docker_compose} up -d --build

echo "building CLI and server"
# set the path to the root of the repo
dir=$(git rev-parse --show-toplevel)
go test -c ./cmd/rekor-cli -o rekor-cli -cover -covermode=count -coverpkg=./...
go test -c ./cmd/rekor-server -o rekor-server -covermode=count -coverpkg=./...

count=0
echo -n "waiting up to 120 sec for system to start"
until [ $(${docker_compose} ps | grep -c "(healthy)") == 4 ];
do
    if [ $count -eq 12 ]; then
       echo "! timeout reached"
       exit 1
    else
       echo -n "."
       sleep 10
       let 'count+=1'
    fi
done

echo
echo "running tests"
REKORTMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
cp $dir/rekor-cli $REKORTMPDIR/rekor-cli
touch $REKORTMPDIR.rekor.yaml
trap "rm -rf $REKORTMPDIR" EXIT
if ! REKORTMPDIR=$REKORTMPDIR go test  -tags=e2e $(go list ./... | grep -v ./tests) ; then
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

if ! docker cp $(docker ps -aqf "name=rekor_rekor-server" -f "name=rekor-rekor-server"):go/rekor-server.cov /tmp/pkg-rekor-server.cov ; then
   # failed to copy code coverage report from server
   echo "Failed to retrieve server code coverage report"
   ${docker_compose} logs --no-color > /tmp/docker-compose.log
   exit 1
fi

# merging coverage reports and filtering out /pkg/generated from final report
hack/tools/bin/gocovmerge /tmp/pkg-rekor-*.cov | grep -v "/pkg/generated/" > /tmp/pkg-rekor-merged.cov
echo "code coverage $(go tool cover -func=/tmp/pkg-rekor-merged.cov | grep -E '^total\:' | sed -E 's/\s+/ /g')"
