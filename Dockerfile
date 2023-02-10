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

FROM golang:1.20.0@sha256:53b7958a2fb14e80163fac58a29bf5bf56b3f9bf85ffb981619c1f2da57e896c AS builder
ENV APP_ROOT=/opt/app-root
ENV GOPATH=$APP_ROOT

WORKDIR $APP_ROOT/src/
ADD go.mod go.sum $APP_ROOT/src/
RUN go mod download

# Add source code
ADD ./cmd/ $APP_ROOT/src/cmd/
ADD ./pkg/ $APP_ROOT/src/pkg/

ARG SERVER_LDFLAGS
RUN go build -ldflags "${SERVER_LDFLAGS}" ./cmd/rekor-server
RUN CGO_ENABLED=0 go build -gcflags "all=-N -l" -ldflags "${SERVER_LDFLAGS}" -o rekor-server_debug ./cmd/rekor-server
RUN go test -c -ldflags "${SERVER_LDFLAGS}" -cover -covermode=count -coverpkg=./... -o rekor-server_test ./cmd/rekor-server

# Multi-Stage production build
FROM golang:1.20.0@sha256:53b7958a2fb14e80163fac58a29bf5bf56b3f9bf85ffb981619c1f2da57e896c as deploy

# Retrieve the binary from the previous stage
COPY --from=builder /opt/app-root/src/rekor-server /usr/local/bin/rekor-server

# Set the binary as the entrypoint of the container
CMD ["rekor-server", "serve"]

# debug compile options & debugger
FROM deploy as debug
RUN go install github.com/go-delve/delve/cmd/dlv@v1.8.0

# overwrite server and include debugger
COPY --from=builder /opt/app-root/src/rekor-server_debug /usr/local/bin/rekor-server

FROM deploy as test
# overwrite server with test build with code coverage
COPY --from=builder /opt/app-root/src/rekor-server_test /usr/local/bin/rekor-server
