# Rekor OID Information

## Description

This document defines Rekor
[OID values](https://github.com/sigstore/sigstore/blob/main/docs/oid-info.md).

Rekor reserves the `1.3.6.1.4.1.57264.3` OID root for all of its values.

## Directory

| OID                       | Name                   | Tag Type               | Description                                                                                                   |
| ------------------------- | ---------------------- | ---------------------- | ------------------------------------------------------------------------------------------------------------- |
| 1.3.6.1.4.1.57264.3.1     | Integrated Time        | INTEGER                | When the data was added to the log.                                                                           |
| 1.3.6.1.4.1.57264.3.2     | Log ID                 | UTF8STRING             | This is a SHA256 hash of the DER-encoded public key for the log at the time the entry was included in the log |
| 1.3.6.1.4.1.57264.3.3     | Log Index              | INTEGER                | The index of the entry in the transparency log.                                                               |
| 1.3.6.1.4.1.57264.3.4     | Verification           |                        | Log Entry Verification data.                                                                                  |
| 1.3.6.1.4.1.57264.3.4.1   | Inclusion Proof        |                        | Proof of inclusion on the transparency log.                                                                   |
| 1.3.6.1.4.1.57264.3.4.1.1 | Checkpoint             | UTF8STRING             | The checkpoint (signed tree head) that the inclusion proof is based on.                                       |
| 1.3.6.1.4.1.57264.3.4.1.2 | Hashes                 | SEQUENCE OF UTF8STRING | A list of hashes required to compute the inclusion proof, sorted in order from leaf to root.                  |
| 1.3.6.1.4.1.57264.3.4.1.3 | Root Hash              | UTF8STRING             | The hash value stored at the root of the merkle tree at the time the proof was generated.                     |
| 1.3.6.1.4.1.57264.3.4.1.4 | Tree Size              | INTEGER                | The size of the merkle tree at the time the inclusion proof was generated.                                    |
| 1.3.6.1.4.1.57264.3.4.2   | Signed Entry Timestamp | UTF8STRING             | Base64 encoded signature of the promise of inclusion.                                                         |

### Notes:

- This is not an exhaustive list of values included in a LogEntry.
- Log Index not included in Inclusion Proof since it's already defined in
  `1.3.6.1.4.1.57264.3.3`.
