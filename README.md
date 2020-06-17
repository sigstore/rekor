# Rekor

Rekor is a cryptographic, immutable, append only software release ledger.

It is planned to be used as part of a cloud native build pipeline, but also could be used
in any context where software packaging (and later planned, files) require attestation.

It uses a trillian backend to store in-toto style metadata into an immutable merkle tree.

The rough idea is that a developer would include a `package.link` along with a software
package release and then use rekor to make a transparency log entry with the same link file.

A receiver of the package would then use rekor to perform a `rekor get` command using the exact
same link file (that they would have received along with the released package)

If the link file is un-tampered, then they know the can trust the sha256 digests of the file, and the
developer's signature embedded within the in-toto link file.

If you had not already noticed, rekor is in very early development, so its not ready for production
use, however if you would like to contribute, then please do.

Its very simple at the moment, but plans are to work more with link files and other manifest structures
to allow automation of  integrity checks and design how other link file content such as materials can
be stored and then queried in a useful manner. 

The trillian components are:

* Rekor CLI
* Rekor trillian personality
* Trillian Log Server
* Trillian Log Signer

# Trillian, what's that?

Trillian provides the transparancy log. It allows population and query of
a distributable merkle tree.

Its sort of like blockchain, without the large electricity bills.

## Create Database

Trillian requires a database, we use MariaDB in this instance. Once this
is installed on your machine edit the `scripts/createdb.sh` with your
database root account credentials and run the script.

## Build Trillian

To run rekor you need to build trillian

```
go get github.com/google/trillian.git
go build ./cmd/trillian_log_server
go build ./cmd/trillian_log_signer
go build ./cmd/trillian_map_server
go build ./cmd/createtree/

```

### Start the tlog server

```
trillian_log_server -http_endpoint=localhost:8090 -rpc_endpoint=localhost:8091 --logtostderr ...
```

### Start the tlog signer

```
trillian_log_signer --logtostderr --force_master --http_endpoint=localhost:8190 -rpc_endpoint=localhost:8191  --batch_size=1000 --sequencer_guard_window=0 --sequencer_interval=200ms
```

## Create a tree (note the return value, you need this for the "tlog_id" flag)

```
./createtree --admin_server=localhost:8091 > logid
cat logid
2587331608088442751
```

### Make an entry:

```
rekor add --tlog_id=2587331608088442751 --linkfile tests/package.link 
```

### Query an entry:

```
rekor get --tlog_id=2587331608088442751 --linkfile tests/package.link 
```

Should your file be returned in full, good news, it matches. 

Should no return occur, then something is up (this of course will be handled
better in time).
