# v0.10.0

** Note: Rekor will not send `application/yaml` responses anymore only `application/json` responses

## Enhancements

* Drop application/yaml content type (https://github.com/sigstore/rekor/pull/933)
* Return 404 if entry isn't found in log (https://github.com/sigstore/rekor/pull/915)
* reuse dsse signature wrappers instead of having a copy (https://github.com/sigstore/rekor/pull/912)

## Others

* update go mod in hack/tools to go1.18 (https://github.com/sigstore/rekor/pull/935)
* Enable Scorecard badge (https://github.com/sigstore/rekor/pull/941)
* Add rekor test harness to presubmit tests (https://github.com/sigstore/rekor/pull/921)
* Bump imjasonh/setup-ko from 0.4 to 0.5 (https://github.com/sigstore/rekor/pull/940)
* update go builder and cosign image (https://github.com/sigstore/rekor/pull/934)
* Bump sigs.k8s.io/release-utils from 0.7.2 to 0.7.3 (https://github.com/sigstore/rekor/pull/937)
* Bump github.com/google/trillian from 1.4.1 to 1.4.2 in /hack/tools (https://github.com/sigstore/rekor/pull/939)
* Bump sigstore/cosign-installer from 2.4.1 to 2.5.0 (https://github.com/sigstore/rekor/pull/936)
* Bump github.com/go-openapi/strfmt from 0.21.2 to 0.21.3 (https://github.com/sigstore/rekor/pull/930)
* Update cosign image in validate-release job (https://github.com/sigstore/rekor/pull/931)
* Bump sigs.k8s.io/release-utils from 0.7.1 to 0.7.2 (https://github.com/sigstore/rekor/pull/927)
* Bump github.com/veraison/go-cose from 1.0.0-alpha.1 to 1.0.0-rc.1 (https://github.com/sigstore/rekor/pull/928)
* Bump actions/dependency-review-action from 2.0.2 to 2.0.4 (https://github.com/sigstore/rekor/pull/925)
* Bump github/codeql-action from 2.1.15 to 2.1.16 (https://github.com/sigstore/rekor/pull/924)
* Bump golang from 1.18.3 to 1.18.4 (https://github.com/sigstore/rekor/pull/919)
* Bump google.golang.org/grpc from 1.47.0 to 1.48.0 (https://github.com/sigstore/rekor/pull/920)
* Bump actions/setup-go from 3.2.0 to 3.2.1 (https://github.com/sigstore/rekor/pull/916)
* Updates on the release job/makefile cleanup (https://github.com/sigstore/rekor/pull/914)
* add changelog for v0.9.1 (https://github.com/sigstore/rekor/pull/911)

## Contributors

* Azeem Shaikh (@azeemshaikh38)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Priya Wadhwa (@priyawadhwa)

# v0.9.1

## Enhancements

* Optimize lookup of attestation from storage layer (https://github.com/sigstore/rekor/pull/909)
* feat: add subject URIs to index for x509 certificates (https://github.com/sigstore/rekor/pull/897)
* ensure log messages have requestID where possible (https://github.com/sigstore/rekor/pull/907)
* Check inactive shards for UUID for /retrieve endpoint (https://github.com/sigstore/rekor/pull/905)

## Bug Fixes

* Fix bug where /retrieve endpoint returns wrong logIndex across shards (https://github.com/sigstore/rekor/pull/908)
* fix: sql syntax in dbcreate script (https://github.com/sigstore/rekor/pull/903)

## Others

* cleanup makefile with generated code; cleanup unused files (https://github.com/sigstore/rekor/pull/910)
* Bump github.com/theupdateframework/go-tuf from 0.3.0 to 0.3.1 (https://github.com/sigstore/rekor/pull/906)
* Pin release-utils to v0.7.1 (https://github.com/sigstore/rekor/pull/904)
* Bump sigstore/cosign-installer from 2.4.0 to 2.4.1 (https://github.com/sigstore/rekor/pull/898)

## Contributors

* Asra Ali (@asraa)
* Bob Callaway (@bobcallaway)
* Priya Wadhwa (@priyawadhwa)
* Romain Aviolat (@xens)
* Sascha Grunert (@saschagrunert)

# v0.9.0

## Enhancements

* Add COSE support to Rekor (https://github.com/sigstore/rekor/pull/867)

## Bug Fixes

* Resolve virtual log index when calling /api/v1/log/entries/retrieve endpoint (https://github.com/sigstore/rekor/pull/894)
* Fix intoto index keys (https://github.com/sigstore/rekor/pull/889)
* ensure fallback logic executes if attestation key is empty when fetching attestation (https://github.com/sigstore/rekor/pull/878)

## Others

* Bump github/codeql-action from 2.1.14 to 2.1.15 (https://github.com/sigstore/rekor/pull/893)
* Bump ossf/scorecard-action from 1.1.1 to 1.1.2 (https://github.com/sigstore/rekor/pull/888)
* Bump github/codeql-action from 2.1.13 to 2.1.14 (https://github.com/sigstore/rekor/pull/885)
* add changelog for v0.8.2 (https://github.com/sigstore/rekor/pull/882)
* Bump github/codeql-action from 2.1.12 to 2.1.13 (https://github.com/sigstore/rekor/pull/880)
* Bump github.com/spf13/cobra from 1.4.0 to 1.5.0 (https://github.com/sigstore/rekor/pull/881)

## Contributors

* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Fredrik Skogman (@kommendorkapten)
* Priya Wadhwa (@priyawadhwa)

# v0.8.2

## Bug Fixes

* ensure fallback logic executes if attestation key is empty when fetching attestation (https://github.com/sigstore/rekor/pull/878)

## Others

* Bump github/codeql-action from 2.1.12 to 2.1.13 (https://github.com/sigstore/rekor/pull/880)
* Bump github.com/spf13/cobra from 1.4.0 to 1.5.0 (https://github.com/sigstore/rekor/pull/881)
* collect docker-compose logs if sharding tests fail, also trim IDs (https://github.com/sigstore/rekor/pull/869)

## Contributors

* Bob Callaway (@bobcallaway)

# v0.8.1

## Bug Fixes

* Allow an expired certificate chain to be uploaded and verified (https://github.com/sigstore/rekor/pull/873)
* Fix indexing bug for intoto attestations (https://github.com/sigstore/rekor/pull/870)

## Others

* Bump actions/dependency-review-action from 1.0.2 to 2 (https://github.com/sigstore/rekor/pull/871)
* Bump sigstore/cosign-installer from 2.3.0 to 2.4.0 (https://github.com/sigstore/rekor/pull/868)
* add changelog for v0.8.0 (https://github.com/sigstore/rekor/pull/866)

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Priya Wadhwa (@priyawadhwa)

# v0.8.0

## Enhancements

* Print total tree size, including inactive shards in `rekor-cli loginfo` (https://github.com/sigstore/rekor/pull/864)
* Allow retrieving entryIDs or UUIDs via `/api/v1/log/entries/retrieve` endpoint (https://github.com/sigstore/rekor/pull/859)
* Improve error message when using ED25519 with HashedRekord type (https://github.com/sigstore/rekor/pull/862)

## Others

* Bump github.com/spf13/viper from 1.11.0 to 1.12.0 (https://github.com/sigstore/rekor/pull/844)
* Bump github.com/go-openapi/validate from 0.21.0 to 0.22.0 (https://github.com/sigstore/rekor/pull/863)
* update go.mod to go1.17 (https://github.com/sigstore/rekor/pull/861)
* update cross-builder image to use go1.17.11 and dockerfile base image (https://github.com/sigstore/rekor/pull/860)
* Bump github/codeql-action from 2.1.11 to 2.1.12 (https://github.com/sigstore/rekor/pull/858)
* Bump ossf/scorecard-action from 1.1.0 to 1.1.1 (https://github.com/sigstore/rekor/pull/857)
* Bump google.golang.org/grpc from 1.46.2 to 1.47.0 (https://github.com/sigstore/rekor/pull/852)
* Bump github.com/secure-systems-lab/go-securesystemslib (https://github.com/sigstore/rekor/pull/853)
* Configure rekor server in e2e tests via env variable (https://github.com/sigstore/rekor/pull/850)
* Bump gopkg.in/ini.v1 from 1.66.5 to 1.66.6 (https://github.com/sigstore/rekor/pull/848)
* Update go-tuf and sigstore/sigstore to non-vulnerable go-tuf version. (https://github.com/sigstore/rekor/pull/847)
* Bump gopkg.in/ini.v1 from 1.66.4 to 1.66.5 (https://github.com/sigstore/rekor/pull/846)

## Contributors

* Carlos Tadeu Panato Junior (@cpanato)
* dhaus67 (@dhaus67)
* Hayden Blauzvern (@haydentherapper)
* Priya Wadhwa (@priyawadhwa)

# v0.7.0

**Breaking Change**: Removed timestamping authority API. This is a breaking API change.
If you are relying on the timestamping authority to issue signed timestamps, create signed timestamps using either OpenSSL or a service such as FreeTSA.

## Enhancements

* Remove timestamping authority (https://github.com/sigstore/rekor/pull/813)
* Limit the number of certificates parsed in a chain (https://github.com/sigstore/rekor/pull/823)
* Retrieve shard tree length if it isn't provided in the config (https://github.com/sigstore/rekor/pull/810)
* Don't try to index on hash for intoto obj if one isn't available (https://github.com/sigstore/rekor/pull/800)
* intoto: add index on materials digest of slsa provenance (https://github.com/sigstore/rekor/pull/793)
* remove URL fetch of keys/artifacts server-side (https://github.com/sigstore/rekor/pull/735)

## Others

* all: remove dependency on deprecated github.com/pkg/errors (https://github.com/sigstore/rekor/pull/834)
* Add back owners for rfc3161 package type (https://github.com/sigstore/rekor/pull/833)
* Bump google-github-actions/auth from 0.7.2 to 0.7.3 (https://github.com/sigstore/rekor/pull/832)
* Bump github/codeql-action from 2.1.10 to 2.1.11 (https://github.com/sigstore/rekor/pull/829)
* Bump google-github-actions/auth from 0.7.1 to 0.7.2 (https://github.com/sigstore/rekor/pull/830)
* Bump google.golang.org/grpc from 1.46.0 to 1.46.2 (https://github.com/sigstore/rekor/pull/828)
* Bump actions/dependency-review-action (https://github.com/sigstore/rekor/pull/825)
* Bump actions/github-script from 6.0.0 to 6.1.0 (https://github.com/sigstore/rekor/pull/826)
* Bump github.com/prometheus/client_golang from 1.12.1 to 1.12.2 (https://github.com/sigstore/rekor/pull/827)
* update go to 1.17.10 in the dockerfile (https://github.com/sigstore/rekor/pull/819)
* Bump github.com/google/trillian from 1.4.0 to 1.4.1 in /hack/tools (https://github.com/sigstore/rekor/pull/818)
* Bump github.com/google/trillian from 1.4.0 to 1.4.1 (https://github.com/sigstore/rekor/pull/817)
* Bump actions/setup-go from 3.0.0 to 3.1.0 (https://github.com/sigstore/rekor/pull/822)
* Bump github/codeql-action (https://github.com/sigstore/rekor/pull/821)
* update release builder images to use go 1.17.10 and cosign image to 1.18.0 (https://github.com/sigstore/rekor/pull/820)
* Bump golangci/golangci-lint-action from 3.1.0 to 3.2.0 (https://github.com/sigstore/rekor/pull/815)
* Bump github/codeql-action from 2.1.9 to 2.1.10 (https://github.com/sigstore/rekor/pull/816)
* Bump github.com/go-openapi/runtime from 0.24.0 to 0.24.1 (https://github.com/sigstore/rekor/pull/811)
* Bump github.com/go-openapi/spec from 0.20.5 to 0.20.6 (https://github.com/sigstore/rekor/pull/802)
* Move trillian/merkly to transparency-dev (https://github.com/sigstore/rekor/pull/807)
* Bump github.com/go-playground/validator/v10 from 10.10.1 to 10.11.0 (https://github.com/sigstore/rekor/pull/803)
* chore(deps): Included dependency review (https://github.com/sigstore/rekor/pull/788)
* Bump github.com/go-openapi/runtime from 0.23.3 to 0.24.0 (https://github.com/sigstore/rekor/pull/799)
* Bump github.com/google/go-cmp from 0.5.7 to 0.5.8 (https://github.com/sigstore/rekor/pull/794)
* Bump sigstore/cosign-installer from 2.2.1 to 2.3.0 (https://github.com/sigstore/rekor/pull/795)
* Bump github/codeql-action from 2.1.8 to 2.1.9 (https://github.com/sigstore/rekor/pull/796)
* Bump google.golang.org/grpc from 1.45.0 to 1.46.0 (https://github.com/sigstore/rekor/pull/791)
* Bump google-github-actions/auth from 0.7.0 to 0.7.1 (https://github.com/sigstore/rekor/pull/790)
* Bump actions/checkout from 3.0.1 to 3.0.2 (https://github.com/sigstore/rekor/pull/786)
* Bump codecov/codecov-action from 3.0.0 to 3.1.0 (https://github.com/sigstore/rekor/pull/785)
* Bump github.com/mitchellh/mapstructure from 1.4.3 to 1.5.0 (https://github.com/sigstore/rekor/pull/782)
* Bump github.com/mediocregopher/radix/v4 from 4.0.0 to 4.1.0 (https://github.com/sigstore/rekor/pull/781)
* Bump anchore/sbom-action from 0.10.0 to 0.11.0 (https://github.com/sigstore/rekor/pull/779)
* Bump actions/checkout from 3.0.0 to 3.0.1 (https://github.com/sigstore/rekor/pull/778)
* Bump github.com/spf13/viper from 1.10.1 to 1.11.0 (https://github.com/sigstore/rekor/pull/777)
* Bump sigstore/cosign-installer from 2.2.0 to 2.2.1 (https://github.com/sigstore/rekor/pull/776)

## Contributors

* Asra Ali (@asraa)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Hayden Blauzvern (@haydentherapper)
* Koichi Shiraishi (@zchee)
* Naveen Srinivasan (@naveensrinivasan)
* Priya Wadhwa (@priyawadhwa)


# v0.6.0

Notice: The server side remote fetching of resources will be removed in the next release

## Enhancements

* Create EntryID for new artifacts and return EntryID to user (https://github.com/sigstore/rekor/pull/623)
* Add search through inactive shards for GET by UUID (https://github.com/sigstore/rekor/pull/750)
* Add in configmap to release for sharding config (https://github.com/sigstore/rekor/pull/766)
* set p.Block after parsing; other cleanup (https://github.com/sigstore/rekor/pull/759)
* Add index to hashed intoto envelope (https://github.com/sigstore/rekor/pull/761)
* Add the SHA256 digest of the intoto payload into the rekor entry (https://github.com/sigstore/rekor/pull/764)
* Add support for providing certificate chain for X509 signature types (https://github.com/sigstore/rekor/pull/747)
* Specify public key for inactive shards in shard config (https://github.com/sigstore/rekor/pull/746)
* Use active tree on server startup (https://github.com/sigstore/rekor/pull/727)
* Require tlog_id when inactive shard config file is passed in (https://github.com/sigstore/rekor/pull/739)
* Replace `trillian_log_server.log_id_ranges` flag with a config file (https://github.com/sigstore/rekor/pull/742)
* Update loginfo API endpoint to return information about inactive shards (https://github.com/sigstore/rekor/pull/738)
* Refactor rekor-cli loginfo (https://github.com/sigstore/rekor/pull/734)
* Get log proofs by Tree ID (https://github.com/sigstore/rekor/pull/733)
* Return virtual index when creating and getting a log entry (https://github.com/sigstore/rekor/pull/725)
* Clearer logging for createAndInitTree (https://github.com/sigstore/rekor/pull/724)
* Change TreeID to be of type `string` instead of `int64` (https://github.com/sigstore/rekor/pull/712)
* Switch to using the swag library for pointer manipulation. (https://github.com/sigstore/rekor/pull/719)
* Make the loginfo command a bit more future/backwards proof. (https://github.com/sigstore/rekor/pull/718)
* Use logRangesFlag in API, route reads based on TreeID (https://github.com/sigstore/rekor/pull/671)
* Set rekor-cli User-Agent header on requests (https://github.com/sigstore/rekor/pull/684)
* create namespace for rekor config in yaml. (https://github.com/sigstore/rekor/pull/680)
* add securityContext to deployment. (https://github.com/sigstore/rekor/pull/678)
* Move k8s objects out of the default namespace (https://github.com/sigstore/rekor/pull/674)

## Bug Fixes

* Fix search without sha prefix (https://github.com/sigstore/rekor/pull/767)
* Fix link in types README (https://github.com/sigstore/rekor/pull/765)
* fix typo in filename (https://github.com/sigstore/rekor/pull/758)
* fix build date format for version command (https://github.com/sigstore/rekor/pull/745)
* fix merge conflict (https://github.com/sigstore/rekor/pull/720)

## Documentation

* Add documentation about Alpine type (https://github.com/sigstore/rekor/pull/697)
* update security process link (https://github.com/sigstore/rekor/pull/685)
* Add intoto type documentation (https://github.com/sigstore/rekor/pull/679)
* Add docs about API stabilitly and deprecation policy (https://github.com/sigstore/rekor/pull/661)

## Others

* Bump github.com/go-openapi/spec from 0.20.4 to 0.20.5 (https://github.com/sigstore/rekor/pull/768)
* Bump anchore/sbom-action from 0.9.0 to 0.10.0 (https://github.com/sigstore/rekor/pull/763)
* Bump github/codeql-action from 2.1.7 to 2.1.8 (https://github.com/sigstore/rekor/pull/762)
* Update release jobs and trillian images (https://github.com/sigstore/rekor/pull/756)
* Bump sigstore/cosign-installer from 2.1.0 to 2.2.0 (https://github.com/sigstore/rekor/pull/757)
* Bump anchore/sbom-action from 0.8.0 to 0.9.0 (https://github.com/sigstore/rekor/pull/754)
* Bump codecov/codecov-action from 2.1.0 to 3 (https://github.com/sigstore/rekor/pull/753)
* Bump github/codeql-action from 2.1.6 to 2.1.7 (https://github.com/sigstore/rekor/pull/752)
* Bump google-github-actions/auth from 0.6.0 to 0.7.0 (https://github.com/sigstore/rekor/pull/751)
* Bump github/codeql-action from 1.1.5 to 2.1.6 (https://github.com/sigstore/rekor/pull/748)
* Bump anchore/sbom-action from 0.7.0 to 0.8.0 (https://github.com/sigstore/rekor/pull/743)
* Bump google.golang.org/protobuf from 1.27.1 to 1.28.0 (https://github.com/sigstore/rekor/pull/744)
* Bump github.com/go-openapi/runtime from 0.23.2 to 0.23.3 (https://github.com/sigstore/rekor/pull/740)
* Bump github/codeql-action from 1.1.4 to 1.1.5 (https://github.com/sigstore/rekor/pull/736)
* Use reusuable release workflow in sigstore/sigstore (https://github.com/sigstore/rekor/pull/729)
* Fix copy/paste mistake in repo name. (https://github.com/sigstore/rekor/pull/730)
* Bump github.com/spf13/cobra from 1.3.0 to 1.4.0 (https://github.com/sigstore/rekor/pull/728)
* Bump golang from `ca70980` to `c7c9458` (https://github.com/sigstore/rekor/pull/722)
* Bump google.golang.org/grpc from 1.44.0 to 1.45.0 (https://github.com/sigstore/rekor/pull/723)
* Add sharding e2e test to Github Actions (https://github.com/sigstore/rekor/pull/714)
* Bump github.com/go-playground/validator/v10 from 10.10.0 to 10.10.1 (https://github.com/sigstore/rekor/pull/717)
* Bump github/codeql-action from 1.1.3 to 1.1.4 (https://github.com/sigstore/rekor/pull/716)
* Add trillian container to existing release. (https://github.com/sigstore/rekor/pull/715)
* Bump golang from `0168c35` to `ca70980` (https://github.com/sigstore/rekor/pull/707)
* Mirror signed release images from GCR to GHCR as part of release (https://github.com/sigstore/rekor/pull/701)
* Bump anchore/sbom-action from 0.6.0 to 0.7.0 (https://github.com/sigstore/rekor/pull/709)
* Bump github.com/go-openapi/runtime from 0.23.1 to 0.23.2 (https://github.com/sigstore/rekor/pull/710)
* Bump sigstore/cosign-installer from 2.0.1 to 2.1.0 (https://github.com/sigstore/rekor/pull/708)
* Generate release yaml artifact. (https://github.com/sigstore/rekor/pull/702)
* Bump actions/upload-artifact from 2.3.1 to 3 (https://github.com/sigstore/rekor/pull/704)
* Go update to 1.17.8 and cosign to 1.6.0 (https://github.com/sigstore/rekor/pull/705)
* Consistent parenthesis use in Makefile (https://github.com/sigstore/rekor/pull/700)
* add code coverage to pull request. (https://github.com/sigstore/rekor/pull/676)
* Bump actions/checkout from 2.4.0 to 3 (https://github.com/sigstore/rekor/pull/698)
* Bump goreleaser/goreleaser-action from 2.9.0 to 2.9.1 (https://github.com/sigstore/rekor/pull/696)
* Bump actions/setup-go from 2.2.0 to 3.0.0 (https://github.com/sigstore/rekor/pull/694)
* Bump github.com/secure-systems-lab/go-securesystemslib (https://github.com/sigstore/rekor/pull/695)
* Bump golangci/golangci-lint-action from 3.0.0 to 3.1.0 (https://github.com/sigstore/rekor/pull/693)
* Bump goreleaser/goreleaser-action from 2.8.1 to 2.9.0 (https://github.com/sigstore/rekor/pull/692)
* Bump golangci/golangci-lint-action from 2.5.2 to 3 (https://github.com/sigstore/rekor/pull/691)
* Bump github/codeql-action from 1.1.2 to 1.1.3 (https://github.com/sigstore/rekor/pull/690)
* Bump github.com/go-openapi/runtime from 0.23.0 to 0.23.1 (https://github.com/sigstore/rekor/pull/689)
* explicitly set permissions for github actions (https://github.com/sigstore/rekor/pull/687)
* Bump sigstore/cosign-installer from 2.0.0 to 2.0.1 (https://github.com/sigstore/rekor/pull/686)
* Bump ossf/scorecard-action from 1.0.3 to 1.0.4 (https://github.com/sigstore/rekor/pull/683)
* Bump github/codeql-action from 1.1.0 to 1.1.2 (https://github.com/sigstore/rekor/pull/682)
* Bump actions/github-script from 5.1.0 to 6 (https://github.com/sigstore/rekor/pull/669)
* Bump github/codeql-action from 1.0.32 to 1.1.0 (https://github.com/sigstore/rekor/pull/668)
* update cross-build and dockerfile to use go 1.17.7 (https://github.com/sigstore/rekor/pull/666)
* Bump gopkg.in/ini.v1 from 1.66.3 to 1.66.4 (https://github.com/sigstore/rekor/pull/664)
* Bump actions/setup-go from 2.1.5 to 2.2.0 (https://github.com/sigstore/rekor/pull/663)
* Bump golang from `301609e` to `fff998d` (https://github.com/sigstore/rekor/pull/662)
* use upstream k8s version lib (https://github.com/sigstore/rekor/pull/657)
* Bump github/codeql-action from 1.0.31 to 1.0.32 (https://github.com/sigstore/rekor/pull/659)
* Bump go.uber.org/zap from 1.20.0 to 1.21.0 (https://github.com/sigstore/rekor/pull/660)
* Bump github.com/go-openapi/strfmt from 0.21.1 to 0.21.2 (https://github.com/sigstore/rekor/pull/656)
* Bump github.com/go-openapi/runtime from 0.22.0 to 0.23.0 (https://github.com/sigstore/rekor/pull/655)
* Update the warning text for the GA release. (https://github.com/sigstore/rekor/pull/654)
* attempting to fix codeowners file (https://github.com/sigstore/rekor/pull/653)
* update release job (https://github.com/sigstore/rekor/pull/651)
* Bump google-github-actions/auth from 0.5.0 to 0.6.0 (https://github.com/sigstore/rekor/pull/652)

## Contributors

* Asra Ali (@asraa)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Eddie Zaneski (@eddiezane)
* Hayden Blauzvern (@haydentherapper)
* John Speed Meyers
* Kenny Leung (@k4leung4)
* Lily Sturmann (@lkatalin)
* Priya Wadhwa (@priyawadhwa)
* Scott Nichols (@n3wscott)

# v0.5.0

## Highlights

* Add Rekor logo to README (https://github.com/sigstore/rekor/pull/650)
* update API calls to v5 (https://github.com/sigstore/rekor/pull/591)
* Refactor helm type to remove intermediate state. (https://github.com/sigstore/rekor/pull/575)
* Refactor the shard map parsing so we can pass it down into the API object. (https://github.com/sigstore/rekor/pull/564)
* Refactor the alpine type to reduce intermediate state. (https://github.com/sigstore/rekor/pull/573)

## Enhancements

* Add logic to GET artifacts via old or new UUID (https://github.com/sigstore/rekor/pull/587)
* helpful error message for hashedrekord types (https://github.com/sigstore/rekor/pull/605)
* Set Accept header in dynamic counter requests (https://github.com/sigstore/rekor/pull/594)
* Add sharding package and update validators (https://github.com/sigstore/rekor/pull/583)
* rekor-cli: show the url in case of error (https://github.com/sigstore/rekor/pull/581)
* Enable parsing of incomplete minisign keys, to enable re-indexing. (https://github.com/sigstore/rekor/pull/567)
* Cleanups on the TUF pluggable type. (https://github.com/sigstore/rekor/pull/563)
* Refactor the RPM type to remove more intermediate state. (https://github.com/sigstore/rekor/pull/566)
* Do some cleanups of the jar type to remove intermediate state. (https://github.com/sigstore/rekor/pull/561)

## Others

* Update Makefile (https://github.com/sigstore/rekor/pull/621)
* update version comments since dependabot doesn't do it (https://github.com/sigstore/rekor/pull/617)
* Use workload identity provider instead of GitHub Secret for GCR access (https://github.com/sigstore/rekor/pull/600)
* add OSSF scorecard action (https://github.com/sigstore/rekor/pull/599)
* enable the sbom for rekor releases (https://github.com/sigstore/rekor/pull/586)
* Point to the official website (instead of a 404) (https://github.com/sigstore/rekor/pull/580)
* add milestone to closed prs (https://github.com/sigstore/rekor/pull/574)
* Add a Makefile target for the "ko apply" step. (https://github.com/sigstore/rekor/pull/572)
* types/README.md: Corrected documentation link (https://github.com/sigstore/rekor/pull/568)

## Dependencies Updates

* Bump github.com/prometheus/client_golang from 1.12.0 to 1.12.1 (https://github.com/sigstore/rekor/pull/636)
* Bump github.com/go-openapi/runtime from 0.21.1 to 0.22.0 (https://github.com/sigstore/rekor/pull/635)
* Bump github.com/go-openapi/swag from 0.19.15 to 0.20.0 (https://github.com/sigstore/rekor/pull/634)
* Bump golang from `f71d4ca` to `301609e` (https://github.com/sigstore/rekor/pull/627)
* Bump golang from `0fa6504` to `f71d4ca` (https://github.com/sigstore/rekor/pull/624)
* Bump google.golang.org/grpc from 1.43.0 to 1.44.0 (https://github.com/sigstore/rekor/pull/622)
* Bump github/codeql-action from 1.0.29 to 1.0.30 (https://github.com/sigstore/rekor/pull/619)
* Bump ossf/scorecard-action from 1.0.1 to 1.0.2 (https://github.com/sigstore/rekor/pull/618)
* bump swagger and go mod tidy (https://github.com/sigstore/rekor/pull/616)
* Bump github.com/go-openapi/runtime from 0.21.0 to 0.21.1 (https://github.com/sigstore/rekor/pull/614)
* Bump github.com/go-openapi/errors from 0.20.1 to 0.20.2 (https://github.com/sigstore/rekor/pull/613)
* Bump google-github-actions/auth from 0.4.4 to 0.5.0 (https://github.com/sigstore/rekor/pull/612)
* Bump github/codeql-action from 1.0.28 to 1.0.29 (https://github.com/sigstore/rekor/pull/611)
* Bump gopkg.in/ini.v1 from 1.66.2 to 1.66.3 (https://github.com/sigstore/rekor/pull/608)
* Bump github.com/google/go-cmp from 0.5.6 to 0.5.7 (https://github.com/sigstore/rekor/pull/609)
* Update github/codeql-action requirement to 8a4b243fbf9a03a93e93a71c1ec257347041f9c4 (https://github.com/sigstore/rekor/pull/606)
* Bump github.com/prometheus/client_golang from 1.11.0 to 1.12.0 (https://github.com/sigstore/rekor/pull/607)
* Bump ossf/scorecard-action from 0fe1afdc40f536c78e3dc69147b91b3ecec2cc8a to 1.0.1 (https://github.com/sigstore/rekor/pull/603)
* Bump goreleaser/goreleaser-action from 2.8.0 to 2.8.1 (https://github.com/sigstore/rekor/pull/602)
* Bump golang from `8c0269d` to `0fa6504` (https://github.com/sigstore/rekor/pull/597)
* Pin dependencies in github action workflows and Dockerfile (https://github.com/sigstore/rekor/pull/595)
* update release image to use go 1.17.6 (https://github.com/sigstore/rekor/pull/589)
* Bump golang from 1.17.5 to 1.17.6 (https://github.com/sigstore/rekor/pull/588)
* Bump go.uber.org/goleak from 1.1.11 to 1.1.12 (https://github.com/sigstore/rekor/pull/585)
* Bump go.uber.org/zap from 1.19.1 to 1.20.0 (https://github.com/sigstore/rekor/pull/584)
* Bump github.com/go-playground/validator/v10 from 10.9.0 to 10.10.0 (https://github.com/sigstore/rekor/pull/579)
* Bump actions/github-script from 4 to 5 (https://github.com/sigstore/rekor/pull/577)

## Contributors

* Asra Ali (@asraa)
* Bob Callaway (@bobcallaway)
* Carlos Tadeu Panato Junior (@cpanato)
* Dan Lorenc (@dlorenc)
* Jason Hall (@imjasonh)
* Lily Sturmann (@lkatalin)
* Morten Linderud (@Foxboron)
* Nathan Smith (@nsmith5)
* Sylvestre Ledru (@sylvestre)
* Trishank Karthik Kuppusamy (@trishankatdatadog)

# v0.4.0

## Highlights

* Adds hashed rekord type that can be used to upload signatures along with the hashed content signed (https://github.com/sigstore/rekor/pull/501)

## Enhancements

* Update the schema to match that of Trillian repo. The map specific (https://github.com/sigstore/rekor/pull/528)
* allow setting the user-agent string sent from the client (https://github.com/sigstore/rekor/pull/521)
* update key usage for ts cert (https://github.com/sigstore/rekor/pull/504)
* api/index/retrieve: allow searching on indicies with sha1 hashes (https://github.com/sigstore/rekor/pull/499)
* Only include Attestation data if attestation storage enabled (https://github.com/sigstore/rekor/pull/494)
* Fuzzing RequestFromRekor API (https://github.com/sigstore/rekor/pull/488)
* Included pprof for profiling the application. (https://github.com/sigstore/rekor/pull/485)
* refactor release and add signing (https://github.com/sigstore/rekor/pull/483)
* More verbose error message for redis connection failure (https://github.com/sigstore/rekor/pull/479) (https://github.com/sigstore/rekor/pull/480)
* Fixed modtime for reproducible goreleaser (https://github.com/sigstore/rekor/pull/473)
* add goreleaser and cloudbuild for releases (https://github.com/sigstore/rekor/pull/443)
* Add dynamic JS tree size counter (https://github.com/sigstore/rekor/pull/468)
* check that entry UUID == leafHash of returned entry (https://github.com/sigstore/rekor/pull/469)
* chore: upgrade cosign version (https://github.com/sigstore/rekor/pull/465)
* Reproducible builds with trimpath (https://github.com/sigstore/rekor/pull/464)
* correct links, add Table of Contents of sorts (https://github.com/sigstore/rekor/pull/449)
* update go tuf for rsa key impl (https://github.com/sigstore/rekor/pull/446)
* Canonicalize JSON before inserting into trillian (https://github.com/sigstore/rekor/pull/445)
* Export search UUIDs field (https://github.com/sigstore/rekor/pull/438)
* Add a flag to start specifying log index ranges for virtual indices. (https://github.com/sigstore/rekor/pull/435)
* Cleanup some initialization/flag parsing in rekor-server. (https://github.com/sigstore/rekor/pull/433)
* Drop 404 errors down to a warning. (https://github.com/sigstore/rekor/pull/426)
* Cleanup the output of search (the text goes to stderr not stdout). (https://github.com/sigstore/rekor/pull/421)
* remove extradata field from types (https://github.com/sigstore/rekor/pull/418)
* Update usage of ./cmd/rekor-cli/ from `rekor` to `rekor-cli` (https://github.com/sigstore/rekor/pull/417)
* Add TUF type (https://github.com/sigstore/rekor/pull/383)
* Updates to INSTALLATION.md notes (https://github.com/sigstore/rekor/pull/415)
* Update snippets to use `console` type for snippets (https://github.com/sigstore/rekor/pull/410)
* version: add way to display a version when using go get or go install (https://github.com/sigstore/rekor/pull/405)
* Use an in memory timestamping key (https://github.com/sigstore/rekor/pull/402)
* Links are case sensitive (https://github.com/sigstore/rekor/pull/401)
* Installation guide (https://github.com/sigstore/rekor/pull/400)
* Add a SignedTimestampNote (https://github.com/sigstore/rekor/pull/397)
* Provide instructions on verifying releases (https://github.com/sigstore/rekor/pull/399)
* rekor-server: add html page when humans reach the server via the browser (https://github.com/sigstore/rekor/pull/394)
* use go modules to track tools (https://github.com/sigstore/rekor/pull/395)

## Bug Fixes

* bug: fix minisign prehashed entries (https://github.com/sigstore/rekor/pull/639)
* fix timestamp addition and unmarshal (https://github.com/sigstore/rekor/pull/525)
* Correct & parallelize tests (https://github.com/sigstore/rekor/pull/522)
* Fix fuzz go.sum issue (https://github.com/sigstore/rekor/pull/509)
* fix validation error (https://github.com/sigstore/rekor/pull/503)
* Correct Helm index keys (https://github.com/sigstore/rekor/pull/474)
* Fix a bug in x509 certificate handling. (https://github.com/sigstore/rekor/pull/461)
* Fix a conflict from parallel dependabot merges. (https://github.com/sigstore/rekor/pull/456)
* fix tuf metadata marshalling (https://github.com/sigstore/rekor/pull/447)
* Switch DSSE provider to go-securesystemslib (https://github.com/sigstore/rekor/pull/442)
* fix unmarshalling sth (https://github.com/sigstore/rekor/pull/409)
* Fix port flag override (https://github.com/sigstore/rekor/pull/396)
* makefile: small fix on the makefile for the rekor-server (https://github.com/sigstore/rekor/pull/393)

## Dependencies Updates

* Bump github.com/spf13/viper from 1.9.0 to 1.10.0 (https://github.com/sigstore/rekor/pull/531)
* Bump sigstore/cosign-installer from 1.3.1 to 1.4.1 (https://github.com/sigstore/rekor/pull/530)
* Bump the DSSE signing library. (https://github.com/sigstore/rekor/pull/529)
* Bump golang from 1.17.4 to 1.17.5 (https://github.com/sigstore/rekor/pull/527)
* Bump golang from 1.17.3 to 1.17.4 (https://github.com/sigstore/rekor/pull/523)
* Bump gopkg.in/ini.v1 from 1.66.0 to 1.66.2 (https://github.com/sigstore/rekor/pull/520)
* Bump github.com/mitchellh/mapstructure from 1.4.2 to 1.4.3 (https://github.com/sigstore/rekor/pull/517)
* Bump github.com/secure-systems-lab/go-securesystemslib (https://github.com/sigstore/rekor/pull/516)
* Bump gopkg.in/ini.v1 from 1.64.0 to 1.66.0 (https://github.com/sigstore/rekor/pull/513)
* Upgraded go-playground/validator module to v10 (https://github.com/sigstore/rekor/pull/507)
* Bump gopkg.in/ini.v1 from 1.63.2 to 1.64.0 (https://github.com/sigstore/rekor/pull/495)
* Bump github.com/go-openapi/strfmt from 0.21.0 to 0.21.1 (https://github.com/sigstore/rekor/pull/510)
* Bump the trillian import to v1.4.0. (https://github.com/sigstore/rekor/pull/502)
* Bump the trillian versions to v1.4.0 in our docker-compose setup. (https://github.com/sigstore/rekor/pull/500)
* update go.mod for go-fuzz (https://github.com/sigstore/rekor/pull/496)
* Bump sigstore/cosign-installer from 1.3.0 to 1.3.1 (https://github.com/sigstore/rekor/pull/491)
* Bump golang from 1.17.2 to 1.17.3 (https://github.com/sigstore/rekor/pull/482)
* Bump google.golang.org/grpc from 1.41.0 to 1.42.0 (https://github.com/sigstore/rekor/pull/478)
* Bump actions/checkout from 2.3.5 to 2.4.0 (https://github.com/sigstore/rekor/pull/477)
* Bump github.com/go-openapi/runtime from 0.20.0 to 0.21.0 (https://github.com/sigstore/rekor/pull/470)
* bump go-swagger to v0.28.0 (https://github.com/sigstore/rekor/pull/463)
* Bump github.com/in-toto/in-toto-golang from 0.3.2 to 0.3.3 (https://github.com/sigstore/rekor/pull/459)
* Bump actions/checkout from 2.3.4 to 2.3.5 (https://github.com/sigstore/rekor/pull/458)
* Bump github.com/mediocregopher/radix/v4 from 4.0.0-beta.1 to 4.0.0 (https://github.com/sigstore/rekor/pull/460)
* Bump github.com/go-openapi/runtime from 0.19.31 to 0.20.0 (https://github.com/sigstore/rekor/pull/451)
* Bump github.com/go-openapi/spec from 0.20.3 to 0.20.4 (https://github.com/sigstore/rekor/pull/454)
* Bump github.com/go-openapi/validate from 0.20.2 to 0.20.3 (https://github.com/sigstore/rekor/pull/453)
* Bump github.com/go-openapi/strfmt from 0.20.2 to 0.20.3 (https://github.com/sigstore/rekor/pull/452)
* Bump github.com/go-openapi/loads from 0.20.2 to 0.20.3 (https://github.com/sigstore/rekor/pull/450)
* Bump golang from 1.17.1 to 1.17.2 (https://github.com/sigstore/rekor/pull/448)
* Bump google.golang.org/grpc from 1.40.0 to 1.41.0 (https://github.com/sigstore/rekor/pull/441)
* Bump golang.org/x/mod from 0.5.0 to 0.5.1 (https://github.com/sigstore/rekor/pull/440)
* Bump github.com/spf13/viper from 1.8.1 to 1.9.0 (https://github.com/sigstore/rekor/pull/439)
* Bump gopkg.in/ini.v1 from 1.63.0 to 1.63.2 (https://github.com/sigstore/rekor/pull/437)
* Bump github.com/mitchellh/mapstructure from 1.4.1 to 1.4.2 (https://github.com/sigstore/rekor/pull/436)
* Bump gocloud to v0.24.0. (https://github.com/sigstore/rekor/pull/434)
* Bump golang from 1.17.0 to 1.17.1 (https://github.com/sigstore/rekor/pull/432)
* Bump go.uber.org/zap from 1.19.0 to 1.19.1 (https://github.com/sigstore/rekor/pull/431)
* Bump gopkg.in/ini.v1 from 1.62.0 to 1.63.0 (https://github.com/sigstore/rekor/pull/429)
* Bump github.com/go-openapi/runtime from 0.19.30 to 0.19.31 (https://github.com/sigstore/rekor/pull/425)
* Bump github.com/go-openapi/errors from 0.20.0 to 0.20.1 (https://github.com/sigstore/rekor/pull/423)
* Bump github.com/go-openapi/strfmt from 0.20.1 to 0.20.2 (https://github.com/sigstore/rekor/pull/422)
* Bump golang from 1.16.7 to 1.17.0 (https://github.com/sigstore/rekor/pull/413)
* Bump golang.org/x/mod from 0.4.2 to 0.5.0 (https://github.com/sigstore/rekor/pull/412)
* Bump google.golang.org/grpc from 1.39.1 to 1.40.0 (https://github.com/sigstore/rekor/pull/411)
* Bump github.com/go-openapi/runtime from 0.19.29 to 0.19.30 (https://github.com/sigstore/rekor/pull/408)
* Bump go.uber.org/zap from 1.18.1 to 1.19.0 (https://github.com/sigstore/rekor/pull/407)
* Bump golang from 1.16.6 to 1.16.7 (https://github.com/sigstore/rekor/pull/403)
* Bump google.golang.org/grpc from 1.39.0 to 1.39.1 (https://github.com/sigstore/rekor/pull/404)


## Contributors

* Aditya Sirish (@adityasaky)
* Andrew Block (@sabre1041)
* Asra Ali (@asraa)
* Axel Simon (@axelsimon)
* Batuhan Apaydın (@developer-guy)
* Bob Callaway (@bobcallaway)
* Carlos Panato (@cpanato)
* Dan Lorenc (@dlorenc)
* Dan Luhring (@luhring)
* Harry Fallows (@harryfallows)
* Hector Fernandez (@hectorj2f)
* Jake Sanders (@dekkagaijin)
* Jason Hall (@imjasonh)
* Lily Sturmann (@lkatalin)
* Luke Hinds (@lukehinds)
* Marina Moore (@mnm678)
* Mikhail Swift (@mikhailswift)
* Naveen Srinivasan (@naveensrinivasan)
* Robert James Hernandez (@sarcasticadmin)
* Santiago Torres (@SantiagoTorres)
* Tiziano Santoro (@tiziano88)
* Trishank Karthik Kuppusamy (@trishankatdatadog)
* Ville Aikas (@vaikas)
* kpcyrd (@kpcyrd)
