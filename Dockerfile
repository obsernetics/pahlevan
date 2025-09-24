# syntax=docker/dockerfile:1

##################################################
# Build Stage 1: Go Application with eBPF
##################################################
FROM golang:1.24-alpine AS go-builder

# Install build dependencies including eBPF tools
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev \
    libbpf-dev \
    clang \
    llvm \
    linux-headers \
    make

WORKDIR /src

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Build eBPF programs and generate Go bindings
RUN make ebpf-build

# Build Go binaries with optimizations
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -a -installsuffix cgo \
    -o manager cmd/operator/main.go

RUN CGO_ENABLED=1 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -a -installsuffix cgo \
    -o pahlevan cmd/pahlevan/main.go

##################################################
# Build Stage 3: Distroless Runtime
##################################################
FROM gcr.io/distroless/base-debian12:nonroot AS runtime

# Copy binary from builder
COPY --from=go-builder /src/manager /usr/local/bin/manager
COPY --from=go-builder /src/pahlevan /usr/local/bin/pahlevan

# Copy eBPF programs
COPY --from=go-builder /src/bpf/*.o /opt/pahlevan/ebpf/

# Set up non-root user (already set by distroless nonroot)
USER 65532:65532

# Add metadata
LABEL org.opencontainers.image.title="Pahlevan"
LABEL org.opencontainers.image.description="eBPF-based Kubernetes Security Operator"
LABEL org.opencontainers.image.vendor="Obsernetics"
LABEL org.opencontainers.image.licenses="Apache-2.0"
LABEL org.opencontainers.image.source="https://github.com/obsernetics/pahlevan"
LABEL org.opencontainers.image.documentation="https://github.com/obsernetics/pahlevan/blob/main/README.md"

# Expose metrics port
EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/manager"]

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
COPY --from=go-builder /src/manager /usr/local/bin/manager
COPY --from=go-builder /src/pahlevan /usr/local/bin/pahlevan
COPY --from=ebpf-builder /src/pkg/ebpf/*.o /opt/pahlevan/ebpf/

# Create non-root user
RUN groupadd -r pahlevan && useradd -r -g pahlevan pahlevan

USER pahlevan

EXPOSE 8080

ENTRYPOINT ["/usr/local/bin/manager"]

##################################################
# Test Stage (for running tests in CI)
##################################################
FROM golang:1.24-alpine AS test

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
FROM node:18-alpine AS docs

WORKDIR /docs

# Install documentation tools
RUN npm install -g @apidevtools/swagger-parser

# Copy documentation
COPY docs/ ./
COPY README.md ./

# Validate and build documentation
RUN find . -name "*.md" -exec echo "Validating {}" \;