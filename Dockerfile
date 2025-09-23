# Build stage
FROM golang:1.24-alpine AS builder

# Install dependencies for eBPF compilation
RUN apk add --no-cache \
    clang \
    llvm \
    make \
    git \
    libbpf-dev \
    linux-headers

WORKDIR /workspace

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download dependencies
RUN go mod download

# Copy the source code
COPY . .

# Build eBPF programs
RUN make ebpf-build

# Build the manager binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o manager cmd/operator/main.go

# Build the CLI binary
RUN CGO_ENABLED=1 GOOS=linux go build -a -installsuffix cgo -o pahlevan cmd/pahlevan/main.go

# Final stage
FROM alpine:3.19

# Install runtime dependencies
RUN apk add --no-cache \
    ca-certificates \
    libbpf \
    iproute2 \
    && rm -rf /var/cache/apk/*

# Create non-root user
RUN addgroup -g 65532 -S nonroot && \
    adduser -u 65532 -S nonroot -G nonroot

WORKDIR /

# Copy the binary from builder stage
COPY --from=builder /workspace/manager .
COPY --from=builder /workspace/pahlevan .

# Copy configuration files
COPY --from=builder /workspace/config/ ./config/

# Use non-root user
USER 65532:65532

ENTRYPOINT ["/manager"]