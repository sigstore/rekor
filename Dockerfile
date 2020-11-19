FROM golang:alpine AS builder

WORKDIR /go/src/github.com/projectrekor/rekor-server/
ADD go.mod go.sum /go/src/github.com/projectrekor/rekor-server/
RUN go mod download

# Add source code
ADD ./ /go/src/github.com/projectrekor/rekor-server/

RUN go build && \
    mv ./rekor-server /usr/bin/rekor-server

# Multi-Stage production build
FROM alpine

RUN apk add --update ca-certificates

# Retrieve the binary from the previous stage
COPY --from=builder /usr/bin/rekor-server /usr/local/bin/rekor-server

# Set the binary as the entrypoint of the container
CMD ["rekor-server", "serve"]