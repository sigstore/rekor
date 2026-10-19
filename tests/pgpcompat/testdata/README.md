# Legacy PGP upload fixtures

- `issue2948.json` is the request from
  https://github.com/sigstore/rekor/issues/2948, with line wrapping removed from
  base64 values. The artifact, signature, and key exactly match the `repomd`
  fixtures in `pkg/pki/pgp/testdata`. The signature is v3; the RSA key is v4.
- `legacy-v3.rpm` and `legacy-v3.key` are the RPM and public key from
  `pkg/types/rpm/tests` immediately before commit
  `86e005525f81e2ed2a04845befcbfa6642a58437` (the OpenPGP migration). They
  exercise a real RPM using v3 header and payload signatures.

The canonical SHA-256 expectations in `compat_test.go` were captured from
`f81ede4b` using its pgpkeys-eu replacement. The RPM baseline additionally used
go-rpmutils' `pgp3` build tag. The compatibility tests now require neither.

Run `go test ./tests/pgpcompat` within Rekor. These public API tests were also
run successfully from a separate consumer module without a crypto replacement.

## HTTP comparison with v1.5.3

Validated on 2026-09-15 against an unmodified checkout of the `v1.5.3` tag
(`7d9dcffcc27c4912e7d17fc768db01aa2d5cf26c`). Both servers were built with
Go 1.27.1 and `CGO_ENABLED=0`, using their respective pinned dependencies,
and ran against separate new trees in a local Trillian instance.

| Upload | v1.5.3 | Patched server |
| --- | --- | --- |
| Issue 2948, armored signature | 201 | 201 |
| Issue 2948, binary signature | 201 | 201 |
| Modern v4 PGP control | 201 | 201 |
| Legacy v3 RPM | 201 | 201 |
| Modern v4 RPM control | 201 | 201 |
| Tampered artifact/payload for each of the five cases | 400 | 400 |
| Issue 2948 with an incorrect key | 400 | 400 |
| Issue 2948 with a truncated signature | 400 | 400 |

All five successful cases returned byte-identical canonical entry bodies
across versions, and therefore identical Merkle leaf hashes. Each entry was
retrieved, its inclusion proof verified with the patched CLI, and its duplicate
submission rejected with HTTP 409. These compare the final HTTP entry bodies,
after the server applies JSON canonicalization, rather than only the output
of the entry implementation's `Canonicalize` method.

Both the v1.5.3 and patched CLIs also successfully resubmitted the issue 2948
and legacy RPM artifacts to both servers (eight client/server/case combinations,
all exit status 0). Those CLI checks exercised existing-entry handling; the
fresh HTTP 201 uploads were tested separately as described above.

The HTTP comparison used temporary local test tooling, which is not included
in this change. Both servers enabled `createLogEntry`, `getLogEntryByUUID`,
`getLogInfo`, `getLogProof`, `getPublicKey`, and `searchLogQuery`. Search-index
storage was disabled. Fresh trees ensured each valid fixture's first submission
returned HTTP 201.
