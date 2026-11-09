# Release

This directory contain the files and scripts to run a Rekor release.

# Cutting a Rekor Release

1. Tag the repository

**WARNING**: Tags should not be updated to a new ref or deleted/recreated after creation. Go provides a [checksum database](https://sum.golang.org/)
that persists an immutable mapping between version and ref, and updating the tag will break clients that have already downloaded the release.

```shell
$ export RELEASE_TAG=<release version, eg "v2.0.2">
$ git tag -s ${RELEASE_TAG} -m "${RELEASE_TAG}"
$ git push upstream ${RELEASE_TAG}
```

Note that `upstream` should be the upstream `sigstore/rekor` repository. You may have to change this if you've configured remotes.

2. Then go to the `Actions` tab and click on the [Cut Release workflow](https://github.com/sigstore/rekor/actions/workflows/cut-release.yml). Note you need
to be in [this list](https://github.com/sigstore/sigstore/blob/main/.github/workflows/reusable-release.yml#L45) to trigger this workflow.

Click to run a workflow and insert the following parameters ("Cosign" is correct, this refers to the artifact signing key):

  - `Release tag`: the tag that use pushed for the release
  - `Key ring for cosign key`: the value is `release-cosign`
  - `Key name for cosign key`: the value is `cosign`

That will trigger a CloudBuild job and will run the release using `goreleaser`, which will publish images to
`gcr.io` and `ghcr.io`, and the binaries will be available in the GitHub release.

If you have permissions to access the project, you can follow the CloudBuild job in the `projectsigstore`(https://console.cloud.google.com/cloud-build/builds?project=projectsigstore) GCP Project.

As the last step of the CloudBuild job, `goreleaser` will create a `draft release` in GitHub.

3. Navigate to the `Draft Release` in the Github repository. Click the `Publish Release` button to make the Release available.

You might want/need to add any extra notes/breaking changes notices, upgrade paths.

4. Post on the `#general` and `#rekor` Slack channels.

5. If it's a significant release, send an announcement email to sigstore-dev@googlegroups.com mailing list.
