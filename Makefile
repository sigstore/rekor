.PHONY: all test clean lint gosec

all: cli server

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

cli: $(SRCS)
	go build ./cmd/rekor-cli

server: $(SRCS)
	go build ./cmd/rekor-server

test:
	go test ./...

clean:
	rm -rf cli server

up:
	docker-compose -f docker-compose.yml build
	docker-compose -f docker-compose.yml up

debug:
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml build rekor-server-debug
	docker-compose -f docker-compose.yml -f docker-compose.debug.yml up rekor-server-debug
