# Rekor

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain. Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's lifecycle. For more details visit the [sigstore website](https://sigstore.dev)

The Rekor project provides a restful API based server for validation and a transparency log for storage. A CLI application is available to make and verify entries, query the transparency log for inclusion
proof, integrity verification of the transparency log or retrieval of entries by either public key or artifact.

Rekor fulfils the signature transparency role of sigstore's software signing
infrastructure. However, Rekor can be run on its own and is designed to be
extensible to working with different manifest schemas and PKI tooling.

For more details on set up a Rekor server,  [visit the following link](https://sigstore.dev/get_started/server/)

For details on CLI usage, [visit the following link](https://sigstore.dev/get_started/client/)

If you're interesting in integration with Rekor, we have an [OpenAPI swagger editor](https://sigstore.dev/swagger/)

A public instance of rekor can be found at [api.sigstore.dev](https://api.sigstore.dev/api/v1/log/)

Rekor allows customized manifests (which term them as types), [type customization is outlined here](https://github.com/sigstore/rekor/tree/main/pkg/types).

## Contributions

We welcome contributions from anyone and are especially interested to hear from
users of Rekor.
