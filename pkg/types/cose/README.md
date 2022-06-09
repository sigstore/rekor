**COSE Type Data Documentation**

This document provides a definition for each field that is not
otherwise described in the [cose
schema](https://github.com/sigstore/rekor/blob/main/pkg/types/cose/v0.0.1/cose_v0_0_1_schema.json). This
document also notes any additional information about the values
associated with each field such as the format in which the data is
stored and any necessary transformations.

**AAD** Additional Authenticated Data.

If the COSE envelope is signed using AAD, the same data must be
provided during upload, otherwise the signature verification will
fail. This data is not stored in Rekor.

**How do you identify an object as an cose object?**

The "Body" field will include an "coseObj" field.

**Recognized content types**

- [in-toto
  statements](https://github.com/in-toto/attestation/tree/main/spec#statement)
  are recognized and parsed. The found subject hashes are indexed so
  they can be searched for.

**What data about the envelope is stored in Rekor**

Only the hash of the payload, the hash of the COSE envelope and the
public key is stored.

If Rekor is configured to use attestation storage, the entire
envelope is also stored. If attestation storage is enabled, the COSE
envelope is stored as an attestation, which means that during
retrieval of the record, the complete envelope is returned in the
`attestation` field, not within the `body`.
