FROM golang:1.24-alpine

# Install dependencies
RUN apk add --no-cache ca-certificates git libbpf iproute2

# Set working directory
WORKDIR /app

# Copy source code
COPY . .

# Build binaries
RUN CGO_ENABLED=0 go build -o manager cmd/operator/main.go && \
    CGO_ENABLED=0 go build -o pahlevan cmd/pahlevan/main.go

# Create non-root user
RUN adduser -D -s /bin/sh -u 65532 nonroot

# Use non-root user
USER nonroot

ENTRYPOINT ["/app/manager"]