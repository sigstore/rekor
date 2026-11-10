# Releasing Rekor

## Publishing updated binaries and container

This guide assumes that `upstream` references `github.com/sigstore/rekor`.

Create and push a new tag. Note that you can't create a tag without creating a release in the GitHub UI, so you'll need to do this locally.

**WARNING**: Tags should not be updated to a new ref or deleted/recreated after creation. Go provides a [checksum database](https://sum.golang.org/)
that persists an immutable mapping between version and ref, and updating the tag will break clients that have already downloaded the release.

```shell
git pull upstream main
export RELEASE_TAG=v1.2.3 # Specify version
git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
git push upstream ${RELEASE_TAG}
```

After the tag is pushed, the [Create release, push container image](https://github.com/sigstore/rekor/actions/workflows/release.yml) workflow will kick off. It will:
* Build and attest the release binaries and create a draft GitHub release
* Build, push, and attest the multi-arch container images on `ghcr.io/sigstore/rekor/rekor-server` and `ghcr.io/sigstore/rekor/rekor-cli`
* Sign the release binaries and container images using the GCP KMS release key and upload the `.sigstore.json` bundles to the draft release
* Copy the container images and their attestations/signatures to `gcr.io/projectsigstore/rekor/rekor-server` and `gcr.io/projectsigstore/rekor/rekor-cli`

Once the workflow finishes, go to [Releases](https://github.com/sigstore/rekor/releases), select
the latest draft release, add release notes, and publish it.

## Updating the infrastructure

Update the [Helm chart](https://github.com/sigstore/helm-charts/tree/main/charts/rekor) to the latest version.

Get the container digest:

```shell
crane digest ghcr.io/sigstore/rekor/rekor-server:v1.2.3 # Specify version
```

Update `charts/rekor/values.yaml` with the new container version and digest.

Update `charts/rekor/Chart.yaml`, bumping `version`, `appVersion`, and the image reference.

Run `helm-docs -g charts/rekor` to update the README.

Create a PR and wait for an oncall engineer to approve and merge.

Afterwards, update the [scaffold](https://github.com/sigstore/helm-charts/tree/main/charts/scaffold)
chart with the bumped Rekor chart version.

An oncall engineer also needs to update the scaffold chart version on the PGI repo.

## Announcements

1. Post on the `#general` and `#rekor` Slack channels.
2. If it's a significant release, send an announcement email to `sigstore-dev@googlegroups.com` mailing list.
