# Copyright 2025 Gosayram Contributors
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

FROM golang:1.25 AS builder
WORKDIR /src

# This arg is passed by docker buildx & contains the target CPU architecture (e.g., amd64, arm64, etc.)
ARG TARGETARCH
ARG TARGETOS

# Version injection arguments
ARG VERSION=dev
ARG COMMIT=none
ARG DATE=unknown

ENV GOARCH=$TARGETARCH
ENV GOOS=$TARGETOS

ENV CGO_ENABLED=0
ENV GOBIN=/usr/local/bin

COPY . .

# Build binaries
RUN \
  --mount=type=cache,target=/root/.cache/go-build \
  --mount=type=cache,target=/go/pkg \
  GO_LDFLAGS="-X 'github.com/Gosayram/openkms/internal/version.Version=${VERSION}' \
              -X 'github.com/Gosayram/openkms/internal/version.Commit=${COMMIT}' \
              -X 'github.com/Gosayram/openkms/internal/version.Date=${DATE}' \
              -s -w" \
  go build -ldflags "${GO_LDFLAGS}" -trimpath -o /src/bin/openkms-server ./cmd/openkms-server && \
  go build -ldflags "${GO_LDFLAGS}" -trimpath -o /src/bin/openkms-cli ./cmd/openkms-cli

# Generate latest ca-certificates
FROM debian:bookworm-slim AS certs
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*

# Use musl busybox since it's statically compiled on all platforms
FROM busybox:musl AS busybox

FROM scratch AS openkms-base

# Create openkms directory with world write permission to allow non root run
RUN --mount=from=busybox,dst=/usr/ ["busybox", "sh", "-c", "mkdir -p /openkms/data && chmod 777 /openkms/data"]

COPY --from=certs /etc/ssl/certs/ca-certificates.crt /etc/ssl/certs/ca-certificates.crt
COPY deploy/files/nsswitch.conf /etc/nsswitch.conf

ENV HOME=/root
ENV USER=root
ENV PATH=/usr/local/bin:/openkms
ENV SSL_CERT_DIR=/etc/ssl/certs
ENV OPENKMS_DATA_DIR=/openkms/data

WORKDIR /openkms

### FINAL STAGES ###

FROM openkms-base AS openkms-server

COPY --from=builder /src/bin/openkms-server /openkms/openkms-server

EXPOSE 8080

ENTRYPOINT ["/openkms/openkms-server"]

FROM openkms-base AS openkms-cli

COPY --from=builder /src/bin/openkms-cli /openkms/openkms-cli

ENTRYPOINT ["/openkms/openkms-cli"]

FROM openkms-server AS openkms-server-debug

ENV PATH /usr/local/bin:/openkms:/busybox

COPY --from=busybox /bin /busybox

# Declare /busybox as a volume to get it automatically in the path to ignore
VOLUME /busybox

RUN ["/busybox/mkdir", "-p", "/bin"]
RUN ["/busybox/ln", "-s", "/busybox/sh", "/bin/sh"]

FROM openkms-base AS openkms-server-slim

COPY --from=builder /src/bin/openkms-server /openkms/openkms-server

EXPOSE 8080

ENTRYPOINT ["/openkms/openkms-server"]

