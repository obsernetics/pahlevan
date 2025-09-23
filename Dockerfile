# syntax=docker/dockerfile:1

##################################################
# Build Stage 1: eBPF Programs
##################################################
FROM ubuntu:22.04 AS ebpf-builder

# Install eBPF build dependencies
RUN apt-get update && apt-get install -y \
    clang \
    llvm \
    libbpf-dev \
    linux-headers-generic \
    make \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src

# Copy eBPF source files
COPY bpf/ ./bpf/
COPY pkg/ebpf/ ./pkg/ebpf/
COPY Makefile ./

# Build eBPF programs
RUN make ebpf-build

##################################################
# Build Stage 2: Go Application
##################################################
FROM golang:1.25-alpine AS go-builder

# Install build dependencies
RUN apk add --no-cache \
    git \
    ca-certificates \
    gcc \
    musl-dev \
    libbpf-dev \
    linux-headers

WORKDIR /src

# Copy go mod files first for better caching
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Copy source code
COPY . .

# Copy eBPF programs from previous stage
COPY --from=ebpf-builder /src/pkg/ebpf/*.o ./pkg/ebpf/

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
COPY --from=ebpf-builder /src/pkg/ebpf/*.o /opt/pahlevan/ebpf/

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
FROM node:18-alpine AS docs

WORKDIR /docs

# Install documentation tools
RUN npm install -g @apidevtools/swagger-parser

# Copy documentation
COPY docs/ ./
COPY README.md ./

# Validate and build documentation
RUN find . -name "*.md" -exec echo "Validating {}" \;