.PHONY: all test clean lint gosec

NONGENSRCS := $(shell find cmd -name "*.go") $(shell find pkg -name "*.go"|grep -v "pkg/generated") pkg/generated/restapi/configure_rekor_server.go
GENSRCS := $(shell find pkg/generated -name "*.go"|grep -v "configure_rekor_server.go")
SRCS := $(NONGENSRCS) ${GENSRCS}

all: cli server

$(GENSRCS): openapi.yaml $(shell find pkg/types/schemas -name "*.json")
	swagger generate client -f openapi.yaml -q -t pkg/generated
	swagger generate server -f openapi.yaml -q -t pkg/generated --exclude-main -A rekor_server --exclude-spec --flag-strategy=pflag

lint: $(SRCS)
	$(GOBIN)/golangci-lint run -v ./...

gosec: $(SRCS)
	$(GOBIN)/gosec ./...

cli: $(SRCS) openapi.yaml
	go build ./cmd/cli

server: $(SRCS) openapi.yaml
	go build ./cmd/server

test:
	go test ./...

clean:
	rm -rf cli server
