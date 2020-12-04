.PHONY: all test clean lint gosec

GENSRCS := $(shell find pkg/generated -name "*.go"|grep -v "configure_rekor_server.go")
SRCS := $(wildcard cmd/**/**.go) ${GENSRCS} $(shell find pkg -name "*.go"|grep -v "pkg/generated") pkg/generated/restapi/configure_rekor_server.go

all: cli server

$(GENSRCS): openapi.yaml
	$(GOBIN)/swagger generate client -f openapi.yaml -q -t pkg/generated --additional-initialism=PKI
	$(GOBIN)/swagger generate server -f openapi.yaml -q -t pkg/generated --additional-initialism=PKI --exclude-main -A rekor_server --exclude-spec --flag-strategy=pflag

lint: $(SRCS)
	$(GOBIN)/golangci-lint run -v ./...

gosec: $(SRCS)
	$(GOBIN)/gosec ./...

cli: $(SRCS)
	go build ./cmd/cli

server: $(SRCS)
	go build ./cmd/server

test:
	go test ./...

clean:
	rm -rf cli server
