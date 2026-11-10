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

# Debian 13 (Trixie) image to build binary for distroless/static-debian13
FROM --platform=$BUILDPLATFORM golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS builder
ARG TARGETOS
ARG TARGETARCH
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./cmd/ $APP_ROOT/src/cmd/
ADD ./pkg/ $APP_ROOT/src/pkg/
ADD ./internal/ $APP_ROOT/src/internal/

ARG SERVER_LDFLAGS
# Build server for deployment
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -trimpath -ldflags "${SERVER_LDFLAGS}" -o rekor-server ./cmd/rekor-server

# Production deployment build
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS deploy
# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server
# Set the binary as the entrypoint of the container
ENTRYPOINT ["/usr/local/bin/rekor-server"]
CMD ["serve"]

# Local deployment build (includes a shell and curl)
FROM golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS local-deploy
# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server
# Set the binary as the entrypoint of the container
ENTRYPOINT ["/usr/local/bin/rekor-server"]
CMD ["serve"]

# Cross-compile dlv for the debug stage
FROM builder AS dlvbuilder
ARG TARGETOS
ARG TARGETARCH
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT
# Create a directory where 'go install' may install the cross-compiled binary,
# if the build and target platform differ.
RUN mkdir -p /opt/app-root/bin/${TARGETOS}_${TARGETARCH}
# Install dlv
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go install github.com/go-delve/delve/cmd/dlv@latest

# Build debug binary
FROM builder AS debug-builder
ARG TARGETOS
ARG TARGETARCH
ARG SERVER_LDFLAGS
# Build server for debugger with compiler optimizations disabled
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -gcflags "all=-N -l" -trimpath -ldflags "${SERVER_LDFLAGS}" -o rekor-server_debug ./cmd/rekor-server

# Multi-stage debugger build
FROM golang:1.27.3-trixie@sha256:c65ecfe613b539ac74c62a4c3b2c27e8f8a6076384c8f27e8a3c0f3be17cc385 AS debug
ARG TARGETOS
ARG TARGETARCH
# Copy dlv binary, either from bin/ when the build and target platform are the same, or
# from bin/TARGETOS_TARGETARCH when the platforms are different.
COPY --from=dlvbuilder /opt/app-root/bin/dlv* /opt/app-root/bin/${TARGETOS}_${TARGETARCH}/dlv* /usr/local/bin/
# Overwrite server binary
COPY --from=debug-builder /opt/app-root/src/rekor-server_debug /usr/local/bin/rekor-server
# Set the binary as the entrypoint of the container
ENTRYPOINT ["/usr/local/bin/rekor-server"]
CMD ["serve"]

# Build test binary with code coverage
FROM builder AS test-builder
ARG TARGETOS
ARG TARGETARCH
ARG SERVER_LDFLAGS
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} go build -ldflags "${SERVER_LDFLAGS}" -cover -covermode=count -coverpkg=./... -o rekor-server_test ./cmd/rekor-server

FROM local-deploy AS test
# overwrite server with test build with code coverage
COPY --from=test-builder /opt/app-root/src/rekor-server_test /usr/local/bin/rekor-server
RUN mkdir -p /go/coverage

# Build CLI for deployment
FROM builder AS cli-builder
ARG TARGETOS
ARG TARGETARCH
ARG CLI_LDFLAGS
RUN GOOS=${TARGETOS} GOARCH=${TARGETARCH} CGO_ENABLED=0 go build -trimpath -ldflags "${CLI_LDFLAGS}" -o rekor-cli ./cmd/rekor-cli

# Production CLI deployment build
FROM gcr.io/distroless/static-debian13:nonroot@sha256:25ac8f0c3b2334a9eb05452266bd4697864a8c8ef0ef71e5e6480d7f92868329 AS deploy-cli
COPY --from=cli-builder /opt/app-root/src/rekor-cli /usr/local/bin/rekor-cli
ENTRYPOINT ["/usr/local/bin/rekor-cli"]
