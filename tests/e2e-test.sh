#!/bin/bash
#set -ex
testdir=$(dirname "$0")

echo "starting services"
docker-compose up -d

echo "building CLI and server"
go build -o rekor-cli ./cmd/cli
go build -o rekor-server ./cmd/server

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
TMPDIR="$(mktemp -d -t rekor_test)"
touch $TMPDIR.rekor.yaml
trap "rm -rf $TMPDIR" EXIT
TMPDIR=$TMPDIR go test -tags=e2e ./tests/