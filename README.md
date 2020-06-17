# Rekor

Rekor is a (planned to be) cloud native cryptographic, immutable, append only software
release ledger.

It uses a trillian backend to store in-toto style metadata into an immutable merkle tree.

The rough idea is that a developer would include a `package.link` along with a software
package release and then use rekor to make a transparency log entry with the same link file.

A receiver of the package would then use rekor to perform a `rekor get` command using the exact
same link file (that they would have received along with the released package)

If the link file is un-tampered, then they know the can trust the sha256 digests of the file, and the
developer's signature embedded within the in-toto link file.

If you had not already noticed, rekor is in very early development, so its not ready for production
use, however if you would like to contribute, then please do.

Its very simple at the moment, but plans are to work more with link files to allow automation of 
integrity checks and design how other link file content such as materials can be stored and then
queried in a useful manner. 

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

## Run the log server

```
trillian_log_server -http_endpoint=localhost:8090 -rpc_endpoint=localhost:8091 --logtostderr ...
I0606 12:21:47.030302   93568 quota_provider.go:48] Using MySQL QuotaManager
I0606 12:21:47.030642   93568 main.go:150] RPC server starting on localhost:8090
I0606 12:21:47.030696   93568 main.go:134] HTTP server starting on localhost:8091
I0606 12:21:47.031021   93568 main.go:159] Deleted tree GC started
```

## Create t-log (note the return value, you need this for `tlog_id`)

```
./createtree --admin_server=localhost:8091 > logid
cat logid
8829762373747052461
```

### Start the tlog server

```
trillian_log_server -http_endpoint=localhost:8090 -rpc_endpoint=localhost:8091 --logtostderr ...
```

### Start the tlog signer

```
trillian_log_signer --logtostderr --force_master --http_endpoint=localhost:8190 -rpc_endpoint=localhost:8191  --batch_size=1000 --sequencer_guard_window=0 --sequencer_interval=200ms
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