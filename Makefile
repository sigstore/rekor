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

.PHONY: all test clean clean-gen lint gosec ko sign-container cross-cli

all: rekor-cli rekor-server

GENSRC = pkg/generated/client/%.go pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml $(shell find pkg/types -iname "*.json")
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_rekor_server.go $(GENSRC)
TOOLS_DIR := hack/tools
TOOLS_BIN_DIR := $(abspath $(TOOLS_DIR)/bin)
BIN_DIR := $(abspath $(ROOT_DIR)/bin)
GO_INSTALL = ./scripts/go_install.sh


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

# Binaries
SWAGGER_VER := v0.27.0
SWAGGER_BIN := swagger
SWAGGER := $(TOOLS_BIN_DIR)/$(SWAGGER_BIN)-$(SWAGGER_VER)

CLI_PKG=github.com/sigstore/rekor/cmd/rekor-cli/app
CLI_LDFLAGS="-X $(CLI_PKG).gitVersion=$(GIT_VERSION) -X $(CLI_PKG).gitCommit=$(GIT_HASH) -X $(CLI_PKG).gitTreeState=$(GIT_TREESTATE) -X $(CLI_PKG).buildDate=$(BUILD_DATE)"

SERVER_PKG=github.com/sigstore/rekor/cmd/rekor-server/app
SERVER_LDFLAGS="-X $(SERVER_PKG).gitVersion=$(GIT_VERSION) -X $(SERVER_PKG).gitCommit=$(GIT_HASH) -X $(SERVER_PKG).gitTreeState=$(GIT_TREESTATE) -X $(SERVER_PKG).buildDate=$(BUILD_DATE)"

$(GENSRC): $(SWAGGER) $(OPENAPIDEPS)
	$(SWAGGER) generate client -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --default-consumes application/json\;q=1
	$(SWAGGER) generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A rekor_server --exclude-spec --flag-strategy=pflag --default-produces application/json

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
	CGO_ENABLED=0 go build -ldflags $(CLI_LDFLAGS) -o rekor-cli ./cmd/rekor-cli

rekor-server: $(SRCS)
	CGO_ENABLED=0 go build -ldflags $(SERVER_LDFLAGS) -o rekor-server ./cmd/rekor-server

test:
	go test ./...

clean:
	rm -rf dist
	rm -rf hack/tools
	rm -rf rekor-cli rekor-server

clean-gen: clean
	rm -rf $(shell find pkg/generated -iname "*.go"|grep -v pkg/generated/restapi/configure_rekor_server.go)

up:
	docker-compose -f docker-compose.yml build --build-arg SERVER_LDFLAGS=$(SERVER_LDFLAGS)
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build --build-arg SERVER_LDFLAGS=$(SERVER_LDFLAGS) rekor-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up rekor-server-debug

ko:
	# We can't pass more than one LDFLAG via GOFLAGS, you can't have spaces in there.
	CGO_ENABLED=0 GOFLAGS="-ldflags=-X=$(SERVER_PKG).gitCommit=$(GIT_HASH)" ko publish --bare \
                --tags $(GIT_VERSION) --tags $(GIT_HASH) --platform=linux/amd64,linux/arm64 \
                github.com/sigstore/rekor/cmd/rekor-server

sign-container: ko
	cosign sign -key .github/workflows/cosign.key -a GIT_HASH=$(GIT_HASH) ${KO_DOCKER_REPO}:$(GIT_HASH)

## --------------------------------------
## Release
## --------------------------------------

.PHONY: dist-cli
dist-cli:
	mkdir -p dist/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-linux-amd64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=linux GOARCH=arm64 go build -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-linux-arm64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-darwin-amd64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-darwin-arm64 ./cmd/rekor-cli
	CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -ldflags $(CLI_LDFLAGS) -o dist/rekor-cli-windows-amd64.exe ./cmd/rekor-cli

.PHONY: dist-server
dist-server:
	mkdir -p dist/
	CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -ldflags $(SERVER_LDFLAGS) -o dist/rekor-server-linux-amd64 ./cmd/rekor-server

.PHONY: dist
dist: dist-server dist-cli

## --------------------------------------
## Tooling Binaries
## --------------------------------------

$(SWAGGER): ## Build swagger from tools folder.
	GOBIN=$(TOOLS_BIN_DIR) $(GO_INSTALL) github.com/go-swagger/go-swagger/cmd/swagger $(SWAGGER_BIN) $(SWAGGER_VER)
