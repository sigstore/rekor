#!/bin/bash
set -ex
testdir=$(dirname "$0")

docker-compose up -d

# Node
nodedir=${testdir}/node

# First time we should get "Created entry"
out=$(go run ./cmd/cli/ upload \
    --artifact $(< ${nodedir}/url) --sha $(< ${nodedir}/sha) \
    --signature=${nodedir}/sig  --public-key=${nodedir}/key)
if [[ $out != *"Created entry at"* ]]; then
    echo "Expected 'Created entry at', got $out"
fi

# Second time we should get "Entry already exists"
out=$(go run ./cmd/cli/ upload \
    --artifact $(< ${nodedir}/url) --sha $(< ${nodedir}/sha) \
    --signature=${nodedir}/sig  --public-key=${nodedir}/key)
if [[ $out != *"Entry already exists"* ]]; then
    echo "Expected 'Created entry at', got $out"
fi
