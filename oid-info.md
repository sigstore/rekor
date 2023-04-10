# Rekor OID Information

## Description

This document defines Rekor
[OID values](https://github.com/sigstore/sigstore/blob/main/docs/oid-info.md).

Rekor reserves the `1.3.6.1.4.1.57264.3` OID root for all of its values.

## Directory

| OID                   | Name                 | Tag Type     | Description                                                                                                                                                        |
| --------------------- | -------------------- | ------------ | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| 1.3.6.1.4.1.57264.3.1 | TransparencyLogEntry | `UTF8STRING` | Proto serialized [TransparencyLogEntry](https://github.com/sigstore/protobuf-specs/blob/4dbf10bc287d76f1bfa68c05a78f3f5add5f56fe/protos/sigstore_rekor.proto#L89). |
