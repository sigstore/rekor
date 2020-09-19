# Rekor Command Line Interface

Early Development / Experimental use only.

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.  Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and nonrepudiation of an object's lifecycle, based on signed metadata stored within a tamper proof binary (merkle) tree.

The Rekor CLI requires a running instance of the [rekor-server](https://github.com/projectrekor/rekor-server).

The CLI will default to using a rekor server connection of `localhost:3000`, should you wish to use a different address:port, use the `--rekor_server` flag.

## Add an entry

The `add` command sends a file to the transparency log, who then adds the file to the transparency log as a merkle leaf.

`rekor add --linkfile <your/linkfile.link>`

## Get Proof of Entry

`rekor get --linkfile <your/linkfile.link>`

The `get` command performs an inclusion proof request to the transparency log. Atttributes such as the files merkle hash, signed tree root hash are used
to cryptographically verify proof of entry.

## Contributions and Issues

Contributions are welcome, please fork and make a pull request. Likewise if you find an issue, please do raise it.

