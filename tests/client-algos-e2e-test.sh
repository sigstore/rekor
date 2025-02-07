#!/bin/bash
#
# Copyright 2025 The Sigstore Authors.
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

docker_compose="docker compose"
if ! ${docker_compose} version >/dev/null 2>&1; then
    docker_compose="docker-compose"
fi

echo "* starting services with default client signing algorithms"
${docker_compose} up -d

echo "* building CLI"
go build -o rekor-cli ./cmd/rekor-cli
REKOR_CLI=$(pwd)/rekor-cli

function waitForRekorServer () {
  echo -n "* waiting up to 60 sec for system to start"
  count=0

  until [ $(docker ps -a | grep -c "(healthy)") == 3 ];
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
}

function check_log_index () {
  logIndex=$1
  # make sure we can get this log index from rekor
  $REKOR_CLI get --log-index $logIndex --rekor_server http://localhost:3000
  # make sure the entry index matches the log index
  gotIndex=$($REKOR_CLI get --log-index $logIndex --rekor_server http://localhost:3000 --format json | jq -r .LogIndex)
  if [[ "$gotIndex" == $logIndex ]]; then
    echo "New entry has expected virtual log index $gotIndex"
  else
    echo "FAIL: expected virtual log index $logIndex, got $gotIndex"
    exit 1
  fi
}

function collectLogsOnFailure () {
    if [[ "$1" -ne "0" ]]; then
        echo "failure detected, collecting docker-compose logs"
        ${docker_compose} logs --no-color > /tmp/docker-compose.log
        exit $1
    elif ${docker_compose} logs --no-color | grep -q "panic: runtime error:" ; then
        # if we're here, we found a panic
        echo "failing due to panics detected in logs"
        ${docker_compose} logs --no-color > /tmp/docker-compose.log
        exit 1
    fi
    exit 0
}
trap "collectLogsOnFailure \$?" EXIT

# Create temp directory for test artifacts
REKORTMPDIR="$(mktemp -d -t rekor_test.XXXXXX)"
touch $REKORTMPDIR.rekor.yaml
trap "rm -rf $REKORTMPDIR" EXIT

waitForRekorServer

# Test default behavior - should accept all supported algorithms
echo "* testing default client signing algorithms behavior"

# Test with ECDSA
pushd tests/client-algos-testdata || exit 1
if ! $REKOR_CLI upload --artifact file1 --artifact-hash "$(sha256sum file1 | awk '{ print $1 }')" --signature file1.ec.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000 --type hashedrekord; then
    echo "! ERROR: ECDSA upload failed"
    exit 1
else
    echo "* successfully uploaded entry with ECDSA"
fi
popd || exit 1
check_log_index 0

pushd tests/client-algos-testdata || exit 1
if ! $REKOR_CLI upload --artifact file2 --artifact-hash "$(sha256sum file2 | awk '{ print $1 }')" --signature file2.rsa.sig --pki-format=x509 --public-key=rsa_public.pem --rekor_server http://localhost:3000 --type hashedrekord; then
    echo "! ERROR: RSA upload failed"
    exit 1
else
    echo "* successfully uploaded entry with RSA"
fi
popd || exit 1
check_log_index 1

# Stop the rekor server
echo "* stopping rekor server to reconfigure client signing algorithms"
${docker_compose} stop rekor-server

# Create a new compose file with restricted algorithms
COMPOSE_FILE=$REKORTMPDIR/docker-compose-restricted-algos.yaml
cat << EOF > $COMPOSE_FILE
version: '3.4'
services:
  rekor-server:
    build:
      context: .
      target: "deploy"
    command: [
      "rekor-server",
      "serve",
      "--trillian_log_server.address=trillian-log-server",
      "--trillian_log_server.port=8090",
      "--redis_server.address=redis-server",
      "--redis_server.port=6379",
      "--rekor_server.address=0.0.0.0",
      "--rekor_server.signer=memory",
      "--enable_attestation_storage",
      "--attestation_storage_bucket=file:///var/run/attestations",
      "--client-signing-algorithms=rsa-sign-pkcs1-2048-sha256,ed25519-ph",
      # Uncomment this for production logging
      # "--log_type=prod",
      ]
    volumes:
    - "/var/run/attestations:/var/run/attestations:z"
    restart: always # keep the server running
    ports:
      - "3000:3000"
      - "2112:2112"
    healthcheck:
      test: ["CMD", "curl", "-f", "http://localhost:3000/ping"]
      interval: 10s
      timeout: 3s
      retries: 3
      start_period: 5s
EOF

echo "* starting rekor server with restricted client signing algorithms (rsa-sign-pkcs1-2048-sha256, ed25519-ph only)"
${docker_compose} -f $COMPOSE_FILE --project-directory=$PWD up -d
waitForRekorServer

# Test with RSA - should succeed
pushd tests/client-algos-testdata || exit 1
if ! $REKOR_CLI upload --artifact file1 --artifact-hash "$(sha256sum file1 | awk '{ print $1 }')" --signature file1.rsa.sig --pki-format=x509 --public-key=rsa_public.pem --rekor_server http://localhost:3000 --type hashedrekord; then
    echo "! ERROR: RSA upload failed"
    exit 1
else
    echo "* successfully uploaded entry with RSA"
fi
popd || exit 1
check_log_index 0

# Test with ECDSA - should fail
echo "* testing ECDSA upload with restricted algorithms"
pushd tests/client-algos-testdata || exit 1
output=$($REKOR_CLI upload --artifact file1 --artifact-hash "$(sha256sum file1 | awk '{ print $1 }')" --signature file1.ec.sig --pki-format=x509 --public-key=ec_public.pem --rekor_server http://localhost:3000 --type hashedrekord 2>&1)
if [ $? -eq 0 ]; then
    echo "! ERROR: ECDSA upload should have failed but succeeded"
    exit 1
elif ! echo "$output" | grep -q "entry algorithms are not allowed"; then
    echo "! ERROR: ECDSA upload failed but with unexpected error message:"
    echo "$output"
    exit 1
else
    echo "* ECDSA upload failed as expected with restricted algorithms"
fi
popd || exit 1

# Test with RSA and sha512 hash - should fail
echo "* testing RSA and sha512 hash upload with restricted algorithms"
pushd tests/client-algos-testdata || exit 1
output=$($REKOR_CLI upload --artifact file2 --artifact-hash "$(sha512sum file2 | awk '{ print $1 }')" --signature file2.rsa512.sig --pki-format=x509 --public-key=rsa_public.pem --rekor_server http://localhost:3000 --type hashedrekord 2>&1)
if [ $? -eq 0 ]; then
    echo "! ERROR: RSA with SHA512 upload should have failed but succeeded"
    exit 1
elif ! echo "$output" | grep -q "entry algorithms are not allowed"; then
    echo "! ERROR: RSA with SHA512 upload failed but with unexpected error message:"
    echo "$output"
    exit 1
else
    echo "* RSA with SHA512 upload failed as expected with restricted algorithms"
fi
popd || exit 1

# Test with ED25519-PH
echo "* testing ED25519-PH upload with restricted algorithms"
pushd tests/client-algos-testdata || exit 1
if ! $REKOR_CLI upload --artifact file1 --artifact-hash "$(sha512sum file1 | awk '{ print $1 }')" --signature file1.ed25519ph.sig --pki-format=x509 --public-key=ed25519_public.pem --rekor_server http://localhost:3000 --type hashedrekord ; then
    echo "! ERROR: ED25519-PH upload failed"
    exit 1
else
    echo "* successfully uploaded entry with ED25519-PH"
fi
popd || exit 1


# Test with ED25519 no ph
echo "* testing regular ED25519 upload with restricted algorithms"
pushd tests/client-algos-testdata || exit 1
output=$($REKOR_CLI upload --artifact file1 --artifact-hash "$(sha512sum file1 | awk '{ print $1 }')" --signature file1.ed25519.sig --pki-format=x509 --public-key=ed25519_public.pem --rekor_server http://localhost:3000 --type hashedrekord 2>&1)
if [ $? -eq 0 ]; then
    echo "! ERROR: ED25519 upload should have failed but succeeded"
    exit 1
elif ! echo "$output" | grep -q "ed25519: invalid signature"; then
    echo "! ERROR: ED25519 upload failed but with unexpected error message:"
    echo "$output"
    exit 1
else
    echo "* ED25519 upload failed as expected with restricted algorithms"
fi
popd || exit 1


echo "* all tests passed successfully!"
