# syntax=docker/dockerfile:1

##################################################
# Build Stage: Go Application with eBPF
##################################################
FROM golang:1.25-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev \
    libbpf-dev \
    linux-headers \
    clang \
    llvm

WORKDIR /src

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# eBPF Go bindings (*_bpfel.go / *_bpfeb.go) are committed to the repo, so no
# clang/bpf2go codegen step is needed here. Regenerate them out-of-band with
# `make ebpf` on a Linux host with clang + libbpf-dev.

# Build Go binaries with optimizations
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# cilium/ebpf is pure Go (no cgo needed to load eBPF), so build static binaries
# for the distroless runtime. Three binaries ship in one image; the DaemonSet and
# Deployment select which to run via their command + securityContext.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o pahlevan-agent ./cmd/pahlevan-agent

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o pahlevan-operator ./cmd/pahlevan-operator

RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o pahlevan ./cmd/pahlevan

##################################################
# Runtime Stage: Distroless Runtime
##################################################
# Use the plain distroless base (not :nonroot): the agent DaemonSet must run
# privileged for eBPF, while the operator Deployment sets runAsNonRoot itself.
# The effective user is therefore chosen per-workload via securityContext.
FROM gcr.io/distroless/base-debian12 AS runtime

# Copy binaries from builder
COPY --from=go-builder /src/pahlevan-agent /usr/local/bin/pahlevan-agent
COPY --from=go-builder /src/pahlevan-operator /usr/local/bin/pahlevan-operator
COPY --from=go-builder /src/pahlevan /usr/local/bin/pahlevan

# Copy compiled eBPF objects (fallback for non-CO-RE / debugging; the bindings
# are embedded in the agent binary via bpf2go).
COPY --from=go-builder /src/pkg/ebpf/*.o /opt/pahlevan/ebpf/

# Add metadata
LABEL org.opencontainers.image.title="Pahlevan"
LABEL org.opencontainers.image.description="eBPF-based Kubernetes Security Operator"
LABEL org.opencontainers.image.vendor="Obsernetics"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/obsernetics/pahlevan"
LABEL org.opencontainers.image.documentation="https://github.com/obsernetics/pahlevan/blob/main/README.md"

# Expose metrics port
EXPOSE 8080

# Default entrypoint is the operator; the agent DaemonSet overrides `command` to
# run /usr/local/bin/pahlevan-agent.
ENTRYPOINT ["/usr/local/bin/pahlevan-operator"]

##################################################
# Development Stage (for debugging)
##################################################
FROM ubuntu:22.04 AS debug

# Install runtime dependencies and debugging tools
RUN apt-get update && apt-get install -y \
    ca-certificates \
    iproute2 \
    libbpf1 \
    strace \
    gdb \
    curl \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy binaries and eBPF programs
COPY --from=go-builder /src/pahlevan-agent /usr/local/bin/pahlevan-agent
COPY --from=go-builder /src/pahlevan-operator /usr/local/bin/pahlevan-operator
COPY --from=go-builder /src/pahlevan /usr/local/bin/pahlevan
COPY --from=go-builder /src/pkg/ebpf/*.o /opt/pahlevan/ebpf/

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/pahlevan-agent"]

##################################################
# Test Stage (for running tests in CI)
##################################################
FROM golang:1.25-alpine AS test

# Install test dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev \
    libbpf-dev \
    linux-headers \
    make

WORKDIR /src

# Copy everything for testing
COPY . .

# Run tests
RUN go mod download
RUN make test-unit

##################################################
# Documentation Stage (for generating docs)
##################################################
FROM node:25-alpine AS docs

WORKDIR /docs

# Install documentation tools
RUN npm install -g @apidevtools/swagger-parser

# Copy documentation
COPY docs/ ./
COPY README.md ./

# Validate and build documentation
RUN find . -name "*.md" -exec echo "Validating {}" \;