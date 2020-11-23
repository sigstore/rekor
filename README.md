# Rekor Command Line Interface

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.  Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's life-cycle, based on signed metadata stored within a tamper proof binary (merkle) tree.

## Build Rekor CLI

From `rekor/cmd/server`

`go build -o rekor`

## Sign your release

Before using rekor, you are required to sign your release. For now we use GPG
(we plant to extend to other signing formats in the foreseeable future)

You may use either armored or plain binary:

`gpg --armor -u jdoe@example.com --output mysignature.asc --detach-sig
myrelease.tar.gz`

You will also need to export your public key

`gpg --export --armor "jdoe@example.com" > mypublickey.key`

## Upload an entry rekor

The `upload` command sends your public key / signature and artifact URL to the rekor transparency log.

Firstly the rekor command will verify your public key, signature and download
a local copy of the artifact. It will then validate the artifact signing (no
access to your private key is required).

If the validations above pass correctly, the rekor command will construct a JSON
file containing your signature, public key and the artifact URL. This file will
be saved locally to your machines home directory (`.rekor/`). The JSON file will
then be sent to the server, who will in turn do the same validations, before
making an entry to the transparency log.

`rekor upload --rekor-server rekor.dev --signature <artifact-signature> --public-key <your_public_key> --artifact-url <url_to_artifact>`

Note that the `--artifact-url` must be a publically accessable location. For example `--artifact-url https://example.com/releases/latest/my_project.tar.gz`

## Verify Proof of Entry

The `verify` command sends your public key / signature and artifcate URL to the rekor transparency log for verification of entry.

You would typically use this command as a means to  verify an 'inclusion proof'
in that your artifact is stored within the transparency log.

`rekor verify --signature <artifact-signature> --public-key <your_public_key> --artifact-url <url_to_artifact>`

* alternatively you can use a local artifact with `--artifact-url` path

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
./rekor-server serve
2020-09-12T16:32:22.705+0100	INFO	cmd/root.go:87	Using config file: /Users/lukehinds/go/src/github.com/projectrekor/rekor-server/rekor-server.yaml
2020-09-12T16:32:22.705+0100	INFO	app/server.go:55	Starting server...
2020-09-12T16:32:22.705+0100	INFO	app/server.go:61	Listening on 127.0.0.1:3000
```

## Contributions

Rekor is still in its early phase of development, so we welcome contributions
from anyone.
