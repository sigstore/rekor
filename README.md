# Rekor Command Line Interface

Rekór - Greek for “Record”

Rekor's goals are to provide an immutable tamper resistant ledger of metadata generated within a software projects supply chain.  Rekor will enable software maintainers and build systems to record signed metadata to an immutable record. Other parties can then query said metadata to enable them to make informed decisions on trust and non-repudiation of an object's life-cycle, based on signed metadata stored within a tamper proof binary (merkle) tree.

Rekor requires a running instance of the [rekor-server](https://github.com/projectrekor/rekor-server).

## Sign your release

Before using rekor, you are required to sign your release. For now we use GPG
(we plant to extend to other signing formats in the foreseeable future)

You may use either armored or plain binary:

`gpg --armor -u jdoe@example.com --output mysignature.asc --detach-sig
myrelease.tar.gz`

You will also need to export your public key

`gpg --export --armor "jdoe@example.com" > mypublickey.key`

## Upload an entry rekor

The `upload` command sends your public key / signature and artifact URL to the rekor transparency log.

Firstly the rekor command will verify your public key, signature and download
a local copy of the artifact. It will then validate the artifact signing (no
access to your private key is required).

If the validations above pass correctly, the rekor command will construct a JSON
file containing your signature, public key and the artifact URL. This file will
be saved locally to your machines home directory (`.rekor/`). The JSON file will
then be sent to the server, who will in turn do the same validations, before
making an entry to the transparency log.

`rekor upload --rekor-server rekor.dev --signature <artifact-signature> --public-key <your_public_key> --artifact-url <url_to_artifact>`

Note that the `--artifact-url` must be a pubically accessable location. For example `--artifact-url https://example.com/releases/latest/my_project.tar.gz`

## Verify Proof of Entry

The `verify` command sends your public key / signature and artifcate URL to the rekor transparency log for verification of entry.

You would typically use this command as a means to  verify an 'inclusion proof'
in that your artifact is stored within the transparency log.

`rekor-cli upload --signature <artifact-signature> --public-key <your_public_key> --artifact-url <url_to_artifact>`

## Contributions

Rekor is still in its early phase of development, so we welcome contributions
from anyone.
