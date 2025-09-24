# syntax=docker/dockerfile:1

##################################################
# Build Stage: Fast Go Build with Caching
##################################################
FROM golang:1.24-alpine AS builder

# Install build dependencies (including eBPF tools)
RUN apk add --no-cache gcc musl-dev clang llvm linux-headers git make bash && \
    # Install libbpf headers for eBPF compilation
    git clone --depth 1 --branch v1.4.3 https://github.com/libbpf/libbpf.git /tmp/libbpf && \
    make -C /tmp/libbpf/src install_headers && \
    rm -rf /tmp/libbpf

WORKDIR /src

# Copy and download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

# Generate eBPF bindings (required for build)
RUN --mount=type=cache,target=/go/pkg/mod \
    go generate ./...

# Build binaries in parallel with optimizations and caching
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=1 go build \
    -ldflags="-w -s" \
    -o manager cmd/operator/main.go && \
    CGO_ENABLED=1 go build \
    -ldflags="-w -s" \
    -o pahlevan cmd/pahlevan/main.go

##################################################
# Runtime Stage: Minimal Image
##################################################
FROM gcr.io/distroless/static:nonroot AS runtime

# Copy binaries
COPY --from=builder /src/manager /manager
COPY --from=builder /src/pahlevan /pahlevan

# Metadata
LABEL org.opencontainers.image.title="Pahlevan"
LABEL org.opencontainers.image.description="Kubernetes Security Operator"
LABEL org.opencontainers.image.source="https://github.com/obsernetics/pahlevan"

USER 65532:65532
EXPOSE 8080
ENTRYPOINT ["/manager"]