# syntax=docker/dockerfile:1

##################################################
# Build Stage: Fast Go Build with Caching
##################################################
FROM golang:1.24-alpine AS builder

# Install only essential dependencies
RUN apk add --no-cache gcc musl-dev

WORKDIR /src

# Copy and download dependencies first (better layer caching)
COPY go.mod go.sum ./
RUN --mount=type=cache,target=/go/pkg/mod \
    go mod download

# Copy source code
COPY . .

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
FROM gcr.io/distroless/static:nonroot

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