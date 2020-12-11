.PHONY: all test clean lint gosec

all: cli server

GENSRC = pkg/generated/client/%.go pkg/generated/models/%.go pkg/generated/restapi/%.go
OPENAPIDEPS = openapi.yaml $(shell find pkg/types -iname "*.json")
SRCS = $(shell find cmd -iname "*.go") $(shell find pkg -iname "*.go"|grep -v pkg/generated) pkg/generated/restapi/configure_rekor_server.go $(GENSRC)

$(GENSRC): $(OPENAPIDEPS)
	swagger generate client -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated
	swagger generate server -f openapi.yaml -q -r COPYRIGHT.txt -t pkg/generated --exclude-main -A rekor_server --exclude-spec --flag-strategy=pflag

# this exists to override pattern match rule above since this file is in the generated directory but should not be treated as generated code
pkg/generated/restapi/configure_rekor_server.go: $(OPENAPIDEPS)
	

lint:
	$(GOBIN)/golangci-lint run -v ./...

gosec:
	$(GOBIN)/gosec ./...

cli: $(SRCS)
	go build ./cmd/cli

server: $(SRCS)
	go build ./cmd/server

test:
	go test ./...

clean:
	rm -rf cli server
