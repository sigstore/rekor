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

.PHONY: all test clean clean-gen lint gosec

all: rekor-cli rekor-server

GENSRC = pkg/generated/client/%.go pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml $(shell find pkg/types -iname "*.json")
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_rekor_server.go $(GENSRC)

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

CLI_PKG=github.com/sigstore/rekor/cmd/rekor-cli/app
CLI_LDFLAGS="-X $(CLI_PKG).gitVersion=$(GIT_VERSION) -X $(CLI_PKG).gitCommit=$(GIT_HASH) -X $(CLI_PKG).gitTreeState=$(GIT_TREESTATE) -X $(CLI_PKG).buildDate=$(BUILD_DATE)"

SERVER_PKG=github.com/sigstore/rekor/cmd/rekor-server/app
SERVER_LDFLAGS="-X $(SERVER_PKG).gitVersion=$(GIT_VERSION) -X $(SERVER_PKG).gitCommit=$(GIT_HASH) -X $(SERVER_PKG).gitTreeState=$(GIT_TREESTATE) -X $(SERVER_PKG).buildDate=$(BUILD_DATE)"

$(GENSRC): $(OPENAPIDEPS)
	swagger generate client -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --default-consumes application/json\;q=1
	swagger generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A rekor_server --exclude-spec --flag-strategy=pflag --default-produces application/json

# this exists to override pattern match rule above since this file is in the generated directory but should not be treated as generated code
pkg/generated/restapi/configure_rekor_server.go: $(OPENAPIDEPS)
	

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

rekor-cli: $(SRCS)
	CGO_ENABLED=0 go build -ldflags $(CLI_LDFLAGS) -o rekor-cli ./cmd/rekor-cli

rekor-server: $(SRCS)
	CGO_ENABLED=0 go build -ldflags $(SERVER_LDFLAGS) -o rekor-server ./cmd/rekor-server

test:
	go test ./...

clean:
	rm -rf rekor-cli rekor-server

clean-gen: clean
	rm -rf $(shell find pkg/generated -iname "*.go"|grep -v pkg/generated/restapi/configure_rekor_server.go)

up:
	docker-compose -f docker-compose.yml build --build-arg SERVER_LDFLAGS=$(SERVER_LDFLAGS)
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build --build-arg SERVER_LDFLAGS=$(SERVER_LDFLAGS) rekor-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up rekor-server-debug
