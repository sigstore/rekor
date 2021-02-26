# Rekor

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.  Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's life-cycle. For more details visit the [rekor website](https://rekor.dev)

The Rekor project provides a restful API based server for validation and a transparency log for storage. A CLI application is available to make and verify entries, query the transparency log for inclusion
proof, integrity verification of the transparency log or retrieval of entries by either public key or artifact.

For more details on setting up a server,  [visit the following link](https://rekor.dev/get_started/server/)

For details on CLI usage, [visit the following link](https://rekor.dev/get_started/client/)

If you're interesting in integration with rekor, we have an [OpenAPI swagger editor](https://rekor.dev/swagger/)

A public instance of rekor can be found at [api.rekor.dev](https://api.rekor.dev/api/v1/log/)

Rekor allows customized manifests (which term them as types), [type customization is outlined here](https://github.com/sigstore/rekor/tree/main/pkg/types).

## Contributions

Rekor is still in its early phase of development, so we welcome contributions
from anyone.
