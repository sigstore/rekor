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

if [ -z "$SERVER_VERSION" ]; then
    echo "Please indicate which version of rekor to test against by setting SERVER_VERSION"
    exit 1
fi

HARNESS_TESTS="TestUploadVerify TestLogInfo TestGetCLI TestSSH TestJAR TestAPK TestIntoto TestX509 TestEntryUpload"

testdir=$(dirname "$0")

echo "building CLI and server"
go build -o rekor-cli ./cmd/rekor-cli

echo "starting services with version $SERVER_VERSION"
git fetch origin
current_branch=$(git rev-parse --abbrev-ref HEAD)
git checkout $SERVER_VERSION
docker-compose up -d --build
git checkout $current_branch

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
echo "running tests $HARNESS_TESTS"
REKORTMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
touch $REKORTMPDIR.rekor.yaml
trap "rm -rf $REKORTMPDIR" EXIT


for test in $HARNESS_TESTS
do
    echo $test
    if ! REKORTMPDIR=$REKORTMPDIR go test -run $test -v -tags=e2e ./tests/; then 
        docker-compose logs --no-color > /tmp/docker-compose.log
        exit 1
    fi
    if docker-compose logs --no-color | grep -q "panic: runtime error:" ; then
        # if we're here, we found a panic
        echo "Failing due to panics detected in logs"
        docker-compose logs --no-color > /tmp/docker-compose.log
        exit 1
    fi
done
