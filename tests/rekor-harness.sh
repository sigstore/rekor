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

TREE_ID=""

function start_server () {
    server_version=$1
    current_branch=$(git rev-parse --abbrev-ref HEAD)
    git checkout $server_version
    if [ $(docker-compose ps | grep -c "(healthy)") == 0 ]; then
        echo "starting services with version $server_version"
        docker-compose up -d --build
        sleep 30
        make rekor-cli
        export TREE_ID=$(./rekor-cli loginfo --format json --rekor_server http://localhost:3000 --store_tree_state=false | jq -r .TreeID)
    else
        echo "turning down rekor and restarting at version $server_version"
        docker stop $(docker ps --filter name=rekor-server --format {{.ID}})
        
        # Replace log in docker-compose.yml with the Tree ID we want
        search="# Uncomment this for production logging"
        replace="\"--trillian_log_server.tlog_id=$TREE_ID\","
        sed -i "s/$search/$replace/" docker-compose.yml

        docker-compose up -d --build rekor-server
    fi

    count=0
    echo -n "waiting up to 60 sec for system to start"
    until [ $(docker-compose ps | grep -c "(healthy)") == 3 ];
    do
        if [ $count -eq 6 ]; then
            echo "! timeout reached"
            cat docker-compose.yml
            docker-compose logs --no-color > /tmp/docker-compose.log
            exit 1
        else
            echo -n "."
            sleep 10
            let 'count+=1'
        fi
    done
    git checkout $server_version .
    git checkout $current_branch
    echo
}

function build_cli () {
    echo "Building CLI at version $cli_version"
    cli_version=$1
    current_branch=$(git rev-parse --abbrev-ref HEAD)
    git checkout $cli_version
    make rekor-cli
    git checkout $cli_version .
    git checkout $current_branch
}

function run_tests () {
    REKORTMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
    touch $REKORTMPDIR.rekor.yaml
    trap "rm -rf $REKORTMPDIR" EXIT

    go clean -testcache
    if ! REKORTMPDIR=$REKORTMPDIR SERVER_VERSION=$1 CLI_VERSION=$2 go test -run TestHarness -v -tags=e2e ./tests/ ; then 
        docker-compose logs --no-color > /tmp/docker-compose.log
        exit 1
    fi
    if docker-compose logs --no-color | grep -q "panic: runtime error:" ; then
        # if we're here, we found a panic
        echo "Failing due to panics detected in logs"
        docker-compose logs --no-color > /tmp/docker-compose.log
        exit 1
    fi
}

# Get last 2 server versions
git fetch --all
NUM_VERSIONS_TO_TEST=2
VERSIONS=$(git tag --sort=-version:refname | head -n $NUM_VERSIONS_TO_TEST | tac)

# Also add the commit @ HEAD
HEAD=$(git log --pretty="%H" -n 1 )
echo "Also testing at HEAD at commit $HEAD"

VERSIONS="$VERSIONS $HEAD"

echo $VERSIONS

export REKOR_HARNESS_TMPDIR="$(mktemp -d -t rekor_test_harness.XXXXXX)"
docker-compose down

for server_version in $VERSIONS 
do
    start_server $server_version
    for cli_version in $VERSIONS 
    do
        echo "======================================================="
        echo "Running tests with server version $server_version and CLI version $cli_version"

        build_cli $cli_version
        run_tests $server_version $cli_version

        echo "Tests passed successfully."
        echo "======================================================="
    done
done

# Since we add two entries to the log for every test, once all tests are run we should have 2*(($NUM_VERSIONS_TO_TEST+1)^2) entries
make rekor-cli
actual=$(./rekor-cli loginfo --rekor_server http://localhost:3000 --format json --store_tree_state=false | jq -r .ActiveTreeSize)
expected=$((2*(1+$NUM_VERSIONS_TO_TEST)*(1+$NUM_VERSIONS_TO_TEST)))
if [[ ! "$expected" == "$actual" ]]; then
    echo "ERROR: Log had $actual entries instead of expected $expected"
    exit 1
fi

echo "Harness testing successful :)"
