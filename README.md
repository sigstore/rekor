# Rekor

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.
Rekor will enable software maintainers and build systems to record signed metadata to an immutable record.
Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's lifecycle. For more details visit the [sigstore website](https://sigstore.dev)

The Rekor project provides a restful API based server for validation and a transparency log for storage.
A CLI application is available to make and verify entries, query the transparency log for inclusion proof,
integrity verification of the transparency log or retrieval of entries by either public key or artifact.

Rekor fulfils the signature transparency role of sigstore's software signing
infrastructure. However, Rekor can be run on its own and is designed to be
extensible to working with different manifest schemas and PKI tooling.

For more details on set up a Rekor server,  [visit the following link](https://sigstore.dev/get_started/server/)

For details on CLI usage, [visit the following link](https://sigstore.dev/get_started/client/)

If you're interesting in integration with Rekor, we have an [OpenAPI swagger editor](https://sigstore.dev/swagger/)

## Public Instance

A public instance of rekor can be found at [api.sigstore.dev](https://api.sigstore.dev/api/v1/log/)

**IMPORTANT**: This instance is currently operated on a best-effort basis.
We **will take the log down** and reset it with zero notice.
We will improve the stability and publish SLOs over time.

This instance is maintained by the Rekor community.
Interested in helping operate and maintain our production CA system and Transparency Logs?
Please reach out via the [mailing list](https://groups.google.com/g/sigstore-dev).

If you have production use-cases in mind, again - please reach out over email via the [mailing list](https://groups.google.com/g/sigstore-dev).
We are interested in helping on board you!

### Auditing the Instance

We run a job to publish the latest Signed Tree Hashes on GCS.
They are served publicly, and can be found with:

```
gsutil ls gs://rekor-sth/
gs://rekor-sth/sth-1173.json
```

The format is currently:

```
$ gsutil cat gs://rekor-sth/sth-1173.json | jq .
{
  "SignedLogRoot": {
    "key_hint": "Ni+Oy6cvQyY=",
    "log_root": "AAEAAAAAAAAElSB3sp4yw0NFEWsTB6RT5mjr6GCKxVQ8Tlym+P3uKTQwuxZquNPzzd3mAAAAAAAACIUAAA==",
    "log_root_signature": "MEUCIQCb8QHWym7jBvBMFk8ir1ZTqT83zpjE0c90vi7VrTG70wIgBwQmaQ96Od62ODZkdT6r1eVsl4r14tYR1MwQbkNv8ZM="
  },
  "VerifiedLogRoot": {
    "TreeSize": 1173,
    "RootHash": "d7KeMsNDRRFrEwekU+Zo6+hgisVUPE5cpvj97ik0MLs=",
    "TimestampNanos": 1615306636833709600,
    "Revision": 2181,
    "Metadata": ""
  }
}
```

We store them in both raw (unverified) and decoded (verified) formats.
You can verify the signatures against Rekor's public key.

These entries contain the tree length, tree root hash as well as the timestamp.
The (signed) timestamp and index of a (signed) tree hash may be used as an attestation that any entries in the log
prior to this index were witnessed by Rekor before this time.

## Extensibility 

Rekor allows customized manifests (which term them as types), [type customization is outlined here](https://github.com/sigstore/rekor/tree/main/pkg/types).

## Contributions

We welcome contributions from anyone and are especially interested to hear from
users of Rekor.
