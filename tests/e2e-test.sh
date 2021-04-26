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

echo "starting services"
docker-compose up -d

echo "building CLI and server"
go build -o rekor-cli ./cmd/rekor-cli
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
echo "running tests"
TMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
touch $TMPDIR.rekor.yaml
trap "rm -rf $TMPDIR" EXIT
TMPDIR=$TMPDIR go test -tags=e2e ./tests/
docker-compose logs --no-color | grep -q "panic: runtime error:" && echo "Failing due to panics detected in logs" && docker-compose logs --no-color && exit 1
