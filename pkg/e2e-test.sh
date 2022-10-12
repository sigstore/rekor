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

set -e
testdir=$(dirname "$0")

rm -f /tmp/rekor-*.cov
echo "installing gocovmerge"
make gocovmerge
docker kill $(docker ps -q) || true
echo "starting services"
docker-compose -f docker-compose.yml -f docker-compose.test.yml up -d --force-recreate --build

echo "building CLI and server"
# set the path to the root of the repo
dir=$(git rev-parse --show-toplevel)
go test -c ./cmd/rekor-cli -o rekor-cli -cover -covermode=count -coverpkg=./...
go test -c ./cmd/rekor-server -o rekor-server -covermode=count -coverpkg=./...

count=0
echo -n "waiting up to 120 sec for system to start"
until [ $(docker-compose ps | grep -c "(healthy)") == 3 ];
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
if ! REKORTMPDIR=$REKORTMPDIR go test -tags=e2e ./pkg/...; then
   docker-compose logs --no-color > /tmp/docker-compose.log
   exit 1
fi
if docker-compose logs --no-color | grep -q "panic: runtime error:" ; then
   # if we're here, we found a panic
   echo "Failing due to panics detected in logs"
   docker-compose logs --no-color > /tmp/docker-compose.log
   exit 1
fi

echo "generating code coverage"
curl -X GET 0.0.0.0:2345/kill
sleep 5

if ! docker cp $(docker ps -aqf "name=rekor_rekor-server"):go/rekor-server.cov /tmp/rekor-server.cov ; then
   # failed to copy code coverage report from server
   echo "Failed to retrieve server code coverage report"
   docker-compose logs --no-color > /tmp/docker-compose.log
   exit 1
fi

# merging coverage reports and filtering out /pkg/generated from final report
hack/tools/bin/gocovmerge /tmp/rekor-*.cov | grep -v "/pkg/generated/" > /tmp/rekor-merged.cov
echo "code coverage $(go tool cover -func=/tmp/rekor-merged.cov | grep -E '^total\:' | sed -E 's/\s+/ /g')"
