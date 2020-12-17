# Rekor Command Line Interface

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.  Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's life-cycle, based on signed metadata stored within a tamper proof binary (merkle) tree.

## Build Rekor CLI

From `rekor/cmd/cli`

`go build -o rekor`

## Sign your release

Before using rekor, you are required to sign your release. For now we use GPG
(we plant to extend to other signing formats in the foreseeable future)

You may use either armored or plain binary:

`gpg --armor -u jdoe@example.com --output mysignature.asc --detach-sig
myrelease.tar.gz`

You will also need to export your public key

`gpg --export --armor "jdoe@example.com" > mypublickey.key`

## Commands
### Upload An Entry

The `upload` command sends a public key, detached signature and artifact to the Rekor transparency log.

Firstly the rekor command will verify your public key, signature and download
a local copy of the artifact. It will then validate the artifact signing (no
access to your private key is required).

If the validations above pass correctly, the rekor command will construct a JSON
file containing your signature, public key and the artifact. This file will
be saved locally to your machine's home directory (`.rekor/`). The JSON file will
then be sent to the server, who will in turn do the same validations, before
making an entry to the transparency log.

`rekor upload --rekor-server https://rekor.dev/ --signature <url_to_signature> --public-key <url_to_public_key> --artifact <url_to_artifact>`

> Note that the flags `--artifact`, `--signature`, and `--public-key` can either be a path to a file on the local filesystem or be a publically accessable URL. For example `--artifact https://example.com/releases/latest/my_project.tar.gz`

### Verify Proof of Entry

The `verify` command queries the Rekor transparency log to verify the inclusion of an entry.

`rekor verify --signature <url_to_signature> --public-key <url_to_public_key> --artifact <url_to_artifact>`

> Alternatively, you can specify the UUID of an entry to verify by using the `--uuid <entry_uuid>` flag

### Get Entry from Log

The `get` command returns an entry from the transparency log using either the log index or the UUID of the entry

`rekor get --uuid <entry_uuid> --log-index <log_index>`

### Verify Consistency of Log

The `logproof` command returns the required information log to generate a consistency proof of the Rekor transparency log between two specified size.

`rekor logproof --first-size <int> --last-size <int>`

where `--first-size` defaults to `0` which means the beginning of the log

### Get Information about Log

The `loginfo` command returns the current size and root hash value of the transparency log

`rekor loginfo`

# Run a rekor server

## Create Database and populate tables

Trillian requires a database, we use MariaDB for now (others to be explored later). Once this
is installed on your machine edit the `scripts/createdb.sh` with your database root account credentials and run the script.

## Build Trillian

To run rekor you need to build trillian

```
go get github.com/google/trillian.git
go build ./cmd/trillian_log_server
go build ./cmd/trillian_log_signer

```

### Start the tlog server

```
trillian_log_server -http_endpoint=localhost:8090 -rpc_endpoint=localhost:8091 --logtostderr ...
```

### Start the tlog signer

```
trillian_log_signer --logtostderr --force_master --http_endpoint=localhost:8190 -rpc_endpoint=localhost:8191  --batch_size=1000 --sequencer_guard_window=0 --sequencer_interval=200ms
```

## Build Rekor Server

From `rekor/cmd/server`

`go build -o rekor-server`

## Start the rekor server

```
./rekor-server server
rekor-server_1         | 2020-12-16T17:06:22.613Z       INFO    app/serve.go:55 Loading support for pluggable type 'rekord'
rekor-server_1         | 2020-12-16T17:06:22.614Z       INFO    app/serve.go:56 Loading version '0.0.1' for pluggable type 'rekord'
rekor-server_1         | 2020-12-16T17:06:22.624Z       INFO    restapi/server.go:231   Serving rekor server at http://[::]:3000
```

## Contributions

Rekor is still in its early phase of development, so we welcome contributions
from anyone.
