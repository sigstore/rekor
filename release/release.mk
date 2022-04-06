##################
# release section
##################

# used when releasing together with GCP CloudBuild
.PHONY: release
release:
	CLIENT_LDFLAGS="$(CLI_LDFLAGS)" SERVER_LDFLAGS="$(SERVER_LDFLAGS)" goreleaser release --rm-dist --timeout 60m

# used when need to validate the goreleaser
.PHONY: snapshot
snapshot:
	CLIENT_LDFLAGS="$(CLI_LDFLAGS)" SERVER_LDFLAGS="$(SERVER_LDFLAGS)" goreleaser release --skip-sign --skip-publish --snapshot --rm-dist

###########################
# sign section
###########################

.PHONY: sign-container-release
sign-container-release: ko ko-trillian
	GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	./release/ko-sign-release-images.sh

####################
# copy image to GHCR
####################

.PHONY: copy-rekor-server-signed-release-to-ghcr
copy-rekor-server-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/rekor-server:$(GIT_VERSION) $(GHCR_PREFIX)/rekor-server:$(GIT_VERSION)

.PHONY: copy-rekor-cli-signed-release-to-ghcr
copy-rekor-cli-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/rekor-cli:$(GIT_VERSION) $(GHCR_PREFIX)/rekor-cli:$(GIT_VERSION)

.PHONY: copy-trillian-log-server-signed-release-to-ghcr
copy-trillian-log-server-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/trillian_log_server:$(GIT_VERSION) $(GHCR_PREFIX)/trillian_log_server:$(GIT_VERSION)

.PHONY: copy-trillian-log-signer-signed-release-to-ghcr
copy-trillian-log-signer-signed-release-to-ghcr:
	cosign copy $(KO_PREFIX)/trillian_log_signer:$(GIT_VERSION) $(GHCR_PREFIX)/trillian_log_signer:$(GIT_VERSION)

.PHONY: copy-signed-release-to-ghcr
copy-signed-release-to-ghcr: copy-rekor-server-signed-release-to-ghcr copy-rekor-cli-signed-release-to-ghcr copy-trillian-log-signer-signed-release-to-ghcr copy-trillian-log-server-signed-release-to-ghcr

## --------------------------------------
## Dist / maybe we can deprecate
## --------------------------------------

.PHONY: dist-cli
dist-cli:
	mkdir -p dist/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-linux-amd64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -trimpath -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-linux-arm64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-darwin-amd64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-darwin-arm64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -trimpath -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-windows-amd64.exe ./cmd/rekor-cli

.PHONY: dist-server
dist-server:
	mkdir -p dist/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -ldflags $(SERVER_LDFLAGS) -o dist/rekor-server-linux-amd64 ./cmd/rekor-server

.PHONY: dist
dist: dist-server dist-cli
