# OpenPGP v3 signature compatibility

Reference upstream: `github.com/pgpkeys-eu/go-crypto` at commit
`d2a8cc303a65a5643c299cb0ffde2ced6f1e14ee`.

## Directory boundaries

```text
internal/pgpv3/
  upstream/                 Complete, byte-identical upstream files
    LICENSE
    PATENTS
    algorithm/hash.go
    encoding/mpi.go
  adapted/                  Modified upstream implementation
    LICENSE
    signature.go
  signature.go              Rekor-specific detached verification and API wrappers
  packet.go                 Rekor-specific packet framing checks
  sigv3_test.go              Parser and verification regression tests
  upstream_test.go           Checksums enforcing unchanged upstream files
  UPSTREAM.md               This provenance document
```

Go subdirectories are separate packages. The dependency direction is
`pgpv3 -> adapted -> upstream/{algorithm,encoding}`. Callers elsewhere in Rekor
continue to import `internal/pgpv3`. All packages belong to Rekor's module;
there is no nested `go.mod`, module replacement, or required build tag.

## `upstream/`: exact file copies

Every file in this directory is copied in full, including its package declaration,
imports, comments, and formatting. No upstream import paths need rewriting:
these two Go files use only standard-library imports.

| Local file | Upstream file |
| --- | --- |
| `upstream/LICENSE` | `LICENSE` |
| `upstream/PATENTS` | `PATENTS` |
| `upstream/algorithm/hash.go` | `openpgp/internal/algorithm/hash.go` |
| `upstream/encoding/mpi.go` | `openpgp/internal/encoding/mpi.go` |

`TestUpstreamFilesUnmodified` checks the SHA-256 digest of each entire file
against the pinned upstream version. Keep local changes out of this directory.
Lint, formatting, and license-header rewriting exclude it to preserve the bytes.
The complete helper files retain some APIs Rekor does not call; keeping the files
intact makes the provenance and future comparisons straightforward.

## `adapted/`: modified upstream code

`adapted/signature.go` is **not** a byte-for-byte copy. Its BSD license is retained
in `adapted/LICENSE` (an additional unchanged copy of the upstream license).

| Local declaration | Upstream source | Local changes |
| --- | --- | --- |
| `Signature` | `openpgp/packet/signature_v3.go`: `SignatureV3` | Renamed type and issuer field; use ProtonMail's exported enum types and byte slices instead of the fork's internal `encoding.Field`. |
| `Parse` | Same file: `(*SignatureV3).parse` | Return a new signature from a byte slice; rewrite error handling and field reads; reject trailing bytes in the packet body. Use the unchanged upstream hash lookup and MPI decoder through local imports. |
| `readFull` | `openpgp/packet/packet.go`: `readFull` | Return only the error, without the byte count. |
| `readSignatureMPI` | Local adapter around upstream `(*encoding.MPI).ReadFrom` | Return the decoded bytes used by `Signature`; the decoder itself is unchanged in `upstream/encoding/mpi.go`. |
| `PrepareVerify` | `openpgp/packet/signature_v3.go`: `(*SignatureV3).PrepareVerify` | Body is unchanged; receiver type is renamed. |
| `padToKeySize` | `openpgp/packet/packet.go`: `padToKeySize` | Function declaration and body are unchanged; local comment differs. It stays here because it is unexported and this file is already adapted. |
| `(*Signature).Verify` | `openpgp/packet/public_key_v3.go`: `(*PublicKey).VerifySignatureV3` | Move the method onto the local signature type; accept a ProtonMail key; use byte slices; check nil/type mismatches and hash-write errors; return an error instead of the default panic. RSA/DSA verification uses Go's standard-library primitives. |

The adapted package also registers the standard-library hash implementations
used by legacy signatures. Signing, signature serialization, v3 public key
parsing, and the fork's other features are not included.

## Package root: locally authored integration

- `signature.go`: the public wrapper type, forwarding `Parse`, `IsV3Packet`, and
  `VerifyDetached`. Detached verification follows the fork's flow in
  `openpgp/read.go`, but is locally written for already-parsed v3 signatures.
  It selects text/binary hashing, reads the artifact, tries candidate keys, and
  restores the hash state between attempts.
- `packet.go`: `ErrNotV3` and `ParseStrict`, using ProtonMail's opaque packet
  reader and rejecting trailing packets.
- The test files and this document are local code/documentation, not copies of
  upstream files.

This package supports the v3 signatures made with v4 keys reported in
https://github.com/sigstore/rekor/issues/2948. Version 2 signatures share this
encoding and remain supported for compatibility. As in the previous fork's
v3 verifier, verification does not evaluate key expiration or revocation;
historical entries must remain verifiable. Modern signatures continue through
upstream ProtonMail. This package does not define a new acceptance policy for
legacy algorithms.

When changing it, run `go test ./internal/pgpv3/...`, the PGP, rekord, and RPM
entry tests, and `go test ./tests/pgpcompat`. Also check library use from a
separate main module when changing dependency handling. Review upstream parser
and verification fixes for applicability; dependency automation does not update
these copied files or the adapted implementation.
