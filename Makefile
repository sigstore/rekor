#
# Copyright 2021 The Sigstore Authors.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

.PHONY: all test clean clean-gen lint gosec ko ko-local sign-container cross-cli

all: rekor-cli rekor-server

GENSRC = pkg/generated/client/%.go pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml $(shell find pkg/types -iname "*.json")
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_rekor_server.go $(GENSRC)
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
BIN_DIR := $(abspath $(ROOT_DIR)/bin)

PROJECT_ID ?= projectsigstore
RUNTIME_IMAGE ?= gcr.io/distroless/static
# Set version variables for LDFLAGS
GIT_VERSION ?= $(shell git describe --tags --always --dirty)
GIT_HASH ?= $(shell git rev-parse HEAD)
DATE_FMT = +'%Y-%m-%dT%H:%M:%SZ'
SOURCE_DATE_EPOCH ?= $(shell git log -1 --pretty=%ct)
ifdef SOURCE_DATE_EPOCH
    BUILD_DATE ?= $(shell date -u -d "@$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u -r "$(SOURCE_DATE_EPOCH)" "$(DATE_FMT)" 2>/dev/null || date -u "$(DATE_FMT)")
else
    BUILD_DATE ?= $(shell date "$(DATE_FMT)")
endif
GIT_TREESTATE = "clean"
DIFF = $(shell git diff --quiet >/dev/null 2>&1; if [ $$? -eq 1 ]; then echo "1"; fi)
ifeq ($(DIFF), 1)
    GIT_TREESTATE = "dirty"
endif

KO_PREFIX ?= gcr.io/projectsigstore
export KO_DOCKER_REPO=$(KO_PREFIX)

# Binaries
SWAGGER := $(TOOLS_BIN_DIR)/swagger
GO-FUZZ-BUILD := $(TOOLS_BIN_DIR)/go-fuzz-build

REKOR_LDFLAGS=-X sigs.k8s.io/release-utils/version.gitVersion=$(GIT_VERSION) \
              -X sigs.k8s.io/release-utils/version.gitCommit=$(GIT_HASH) \
              -X sigs.k8s.io/release-utils/version.gitTreeState=$(GIT_TREESTATE) \
              -X sigs.k8s.io/release-utils/version.buildDate=$(BUILD_DATE)

CLI_LDFLAGS=$(REKOR_LDFLAGS)
SERVER_LDFLAGS=$(REKOR_LDFLAGS)


$(GENSRC): $(SWAGGER) $(OPENAPIDEPS)
	$(SWAGGER) generate client -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --default-consumes application/json\;q=1 --additional-initialism=TUF
	$(SWAGGER) generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A rekor_server --exclude-spec --flag-strategy=pflag --default-produces application/json --additional-initialism=TUF

.PHONY: validate-openapi
validate-openapi: $(SWAGGER)
	$(SWAGGER) validate openapi.yaml

# this exists to override pattern match rule above since this file is in the generated directory but should not be treated as generated code
pkg/generated/restapi/configure_rekor_server.go: $(OPENAPIDEPS)


lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

gen: $(GENSRC)

rekor-cli: $(SRCS)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(CLI_LDFLAGS)" -o rekor-cli ./cmd/rekor-cli

rekor-server: $(SRCS)
	CGO_ENABLED=0 go build -trimpath -ldflags "$(SERVER_LDFLAGS)" -o rekor-server ./cmd/rekor-server

test:
	go test ./...

fuzz: $(GO-FUZZ-BUILD)
	# This is a hack because of this bug https://github.com/golang/go/issues/44129
	cd tests/fuzz;GOFLAGS=-mod=mod $(GO-FUZZ-BUILD);cd ../../;go mod tidy

clean:
	rm -rf dist
	rm -rf hack/tools/bin
	rm -rf rekor-cli rekor-server
	rm -f *fuzz.zip

clean-gen: clean
	rm -rf $(shell find pkg/generated -iname "*.go"|grep -v pkg/generated/restapi/configure_rekor_server.go)

up:
	docker-compose -f docker-compose.yml build --build-arg SERVER_LDFLAGS="$(SERVER_LDFLAGS)"
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build --build-arg SERVER_LDFLAGS="$(SERVER_LDFLAGS)" rekor-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up rekor-server-debug

ko:
	# rekor-server
	LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/rekor/cmd/rekor-server

	# rekor-cli
	LDFLAGS="$(CLI_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/sigstore/rekor/cmd/rekor-cli

deploy:
	LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) ko apply -f config/

sign-container: ko
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) $(KO_DOCKER_REPO)/rekor-server:$(GIT_HASH)
	cosign sign --key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) $(KO_DOCKER_REPO)/rekor-cli:$(GIT_HASH)

.PHONY: sign-keyless-ci
sign-keyless-ci: ko
	cosign sign --force -a GIT_HASH=$(GIT_HASH) $(KO_DOCKER_REPO)/rekor-server:$(GIT_HASH)
	cosign sign --force -a GIT_HASH=$(GIT_HASH) $(KO_DOCKER_REPO)/rekor-cli:$(GIT_HASH)

.PHONY: ko-local
ko-local:
	LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/rekor/cmd/rekor-server

	LDFLAGS="$(CLI_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--tags $(GIT_VERSION) --tags $(GIT_HASH) --local \
		github.com/sigstore/rekor/cmd/rekor-cli

# This builds the trillian containers we rely on using ko for cross platform support
.PHONY: ko-trillian
ko-trillian:
	LDFLAGS="$(SERVER_LDFLAGS)" GIT_HASH=$(GIT_HASH) GIT_VERSION=$(GIT_VERSION) \
	ko publish --base-import-paths --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/google/trillian/cmd/trillian_log_signer
	ko publish --base-import-paths --bare \
		--platform=all --tags $(GIT_VERSION) --tags $(GIT_HASH) \
		github.com/google/trillian/cmd/trillian_log_server


## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(GO-FUZZ-BUILD): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR);go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/go-fuzz-build github.com/dvyukov/go-fuzz/go-fuzz-build

$(SWAGGER): $(TOOLS_DIR)/go.mod
	cd $(TOOLS_DIR); go build -trimpath -tags=tools -o $(TOOLS_BIN_DIR)/swagger github.com/go-swagger/go-swagger/cmd/swagger

##################
# help
##################

help: # Display help
	@awk -F ':|##' \
		'/^[^\t].+?:.*?##/ (\
			printf "\033[36m%-30s\033[0m %s\n", $$1, $$NF \
		)' $(MAKEFILE_LIST) | sort

include release/release.mk
