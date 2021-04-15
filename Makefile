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
	go build ./cmd/rekor-cli

rekor-server: $(SRCS)
	go build ./cmd/rekor-server

test:
	go test ./...

clean:
	rm -rf rekor-cli rekor-server

clean-gen: clean
	rm -rf $(shell find pkg/generated -iname "*.go"|grep -v pkg/generated/restapi/configure_rekor_server.go)

up:
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build rekor-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up rekor-server-debug
