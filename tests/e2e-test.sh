#!/bin/bash
set -ex
testdir=$(dirname "$0")

docker-compose up -d

go build -o rekor-cli ./cmd/cli

go test -tags=e2e ./tests/
