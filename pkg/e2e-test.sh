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

echo "starting services"
docker-compose up -d

echo "building CLI and server"
dir=$(dirname "$0")
go build -o rekor-cli ./cmd/rekor-cli
go build -o rekor-server ./cmd/rekor-server

count=0
docker kill $(docker ps -q) || true
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
