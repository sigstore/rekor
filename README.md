# Rekor

## Early Development / Experimental use only.

Attestation and provenance of software, its generated artefacts and information on tools used to build said software, relies on an often disparate set of different approaches and data formats. The solutions that do exist, often rely on digests that are stored on insecure systems that are susceptible to tampering and can lead to various attacks such as swapping out of digests , replay attacks.

The goal of rekor would be to create a ledger service, and associated tooling for software maintainers to store metadata and digests of their software source code, artefacts and build process along with binary provenance. The ledger service will then act as a means for users to query said metadata and and assess the trust state / audit record of objects consumed within their own supply chain (for example dependencies).

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software project or supply chain.  Rekor would enable software maintainers and build systems to generate metadata containing signed digests to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and nonrepudiation of an object's lifecycle, based on signed metadata stored within a tamper proof binary (merkle) tree.

Rekor seeks to provide provenance and integrity of the software supply chain.

Provenance deals with systematically capturing metadata describing the relationships among all the elements such as source code, build tools / compiler, processing steps, contextual information and dependencies used. Software provenance can be used for many purposes, such as understanding how an artifact was collected, determining ownership and rights over an artifact for policy decisions, making judgements about information to determine whether to trust an external library, verifying whether the process and steps used to obtain an artifact are compliant with given requirements etc.

Integrity is a control mechanism that examines objects and checks if their integrity is intact and of a non tampered state. This is typically achieved using a cryptographically signed digest of the object (for example, code file, binary, configuration file). The signed digest and then be used to attest the trust status and provide surety that no unauthorised or malicious changes have been made.

It uses a trillian backend to store [in-toto](https://in-toto.io/) style metadata into an immutable merkle tree.

The rough idea is that a developer would include an in-toto style `.link` file along with a software
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

# Other considerations

## Developer Identification

There needs to be a means of fixing a rekor entry to a developer identity. This identity will need cryptographic properties, so that a type of public key can be used to attest manifests stored within rekor as coming from the claimed provider of the manifests. A means to handle key compromise should also be considered, such as the principles utilized in the [TUF framework](https://theupdateframework.io/).

The developer ID would allow queries to rekor to assess compromise impact over other projects.  

It is vitally important to also balance between non repudiation and privacy. Developers should be able to contribute to open source  projects without fear of personal identity exposure leading to risks against their personal safety (for example, should they live within an oppressive regime).
