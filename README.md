# Rekor Command Line Interface

Early Development / Experimental use only.

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.  Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's life-cycle, based on signed metadata stored within a tamper proof binary (merkle) tree.

The Rekor CLI requires a running instance of the [rekor-server](https://github.com/projectrekor/rekor-server).

The CLI will default to using a rekor server connection of `localhost:3000`, should you wish to use a different address:port, use the `--rekor_server` flag.

## Add an entry

The `add` command sends a file to the transparency log, who then adds the file
to the transparency log as a merkle leaf.

`rekor-cli add --rekord <your/yourfile>`

## Get Proof of Entry

`rekor-cli get --rekord <your/yourfile>`

The `get` command performs an inclusion proof request to the transparency log.
Attributes such as the files merkle hash, signed tree root hash are used to
cryptographically verify proof of entry.

## Update consistency proof

Get a consistency proof against the tree between the last seen time and now

This command can be used to monitor the tree for updates, it creates a track
file in `$HOME/.rekor/rekor.json`

`rekor-cli update`

## get leaf

Pass an index and the file is retrieved using a filename according to the merkle
hash.

`rekor-cli getleaf --index 1`

## Contributions and Issues

Contributions are welcome, please fork and make a pull request. Likewise if you
find an issue, please do raise it.
