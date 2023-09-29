[![OpenSSF Scorecard](https://api.securityscorecards.dev/projects/github.com/sigstore/rekor/badge)](https://api.securityscorecards.dev/projects/github.com/sigstore/rekor)

<p align="center">
  <img style="max-width: 100%;width: 300px;" src="https://raw.githubusercontent.com/sigstore/community/main/artwork/rekor/horizontal/color/sigstore_rekor-horizontal-color.svg" alt="Rekor logo"/>
</p>

# Rekor

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.
Rekor will enable software maintainers and build systems to record signed metadata to an immutable record.
Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's lifecycle. For more details visit the [sigstore website](https://sigstore.dev).

The Rekor project provides a restful API based server for validation and a transparency log for storage.
A CLI application is available to make and verify entries, query the transparency log for inclusion proof,
integrity verification of the transparency log or retrieval of entries by either public key or artifact.

Rekor fulfils the signature transparency role of sigstore's software signing
infrastructure. However, Rekor can be run on its own and is designed to be
extensible to working with different manifest schemas and PKI tooling.

[Official Documentation](https://docs.sigstore.dev/rekor/overview).

## Public Instance

Rekor is officially Generally Available with a 1.0.0 release, and follows [semver rules](https://semver.org/) for API stability.
This means production workloads can rely on the Rekor public instance, which has a 24/7 oncall rotation supporting it and offers a 99.5% availability SLO for the following API endpoints:
* `/api/v1/log`
* `/api/v1/log/publicKey`
* `/api/v1/log/proof`
* `/api/v1/log/entries`
* `/api/v1/log/entries/retrieve`

For uptime data on the Rekor public instance, see [https://status.sigstore.dev](https://status.sigstore.dev).

More details on the public instance can be found at [docs.sigstore.dev](https://docs.sigstore.dev/rekor/public-instance).

The attestation size limit for uploads to the public instance is [100KB](https://github.com/sigstore/rekor/blob/18c81d9f4def67c72f630c5406e26d5e568bc83b/cmd/rekor-server/app/root.go#L104). If you need to upload larger files, please run your own instance of Rekor. You can find instructions for doing so in the [installation](https://docs.sigstore.dev/rekor/overview#usage-and-installation) documentation.

### Installation

Please see the [installation](https://docs.sigstore.dev/rekor/overview#usage-and-installation) page for details on how to install the rekor CLI and set up / run
the rekor server

### Usage

For examples of uploading signatures for all the supported types to rekor, see [the types documentation](types.md).

## Extensibility

### Custom schemas / manifests (rekor type)

Rekor allows customized manifests (which term them as types), [type customization is outlined here](https://github.com/sigstore/rekor/tree/main/pkg/types).

### API

If you're interested in integration with Rekor, we have an [OpenAPI swagger editor](https://sigstore.dev/swagger/)

## Security

Should you discover any security issues, please refer to sigstore's [security process](https://github.com/sigstore/.github/blob/main/SECURITY.md)

## Contributions

We welcome contributions from anyone and are especially interested to hear from users of Rekor.

## Additional Documentation

In addition to this README file, this folder contains the additional documentation:
- **oid-info.md**. Rekor OID values.
- **types.md**. Information about how to sign and upload data in different pluggable types.  
