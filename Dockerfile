# syntax=docker/dockerfile:1

##################################################
# Build Stage: Go application (static, no cgo)
##################################################
FROM golang:1.25-alpine AS go-builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

COPY . .

# eBPF Go bindings (*_bpfel.go / *_bpfeb.go) and their embedded objects are
# committed, so no clang/bpf2go codegen is needed here. Regenerate out-of-band
# with `make ebpf` on a Linux host with clang + libbpf-dev.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# cilium/ebpf is pure Go (no cgo needed to load eBPF), so build static binaries.
# Three binaries ship in one image; the DaemonSet/Deployment pick which to run.
RUN CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o pahlevan-agent ./cmd/pahlevan-agent && \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o pahlevan-operator ./cmd/pahlevan-operator && \
    CGO_ENABLED=0 GOOS=linux go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.commit=${COMMIT} -X main.date=${DATE}" \
    -o pahlevan ./cmd/pahlevan

##################################################
# Runtime Stage - distroless (the default build target)
##################################################
# Plain distroless base (not :nonroot): the agent DaemonSet must run privileged
# for eBPF, while the operator Deployment sets runAsNonRoot itself - the effective
# user is chosen per-workload via securityContext.
FROM gcr.io/distroless/base-debian12 AS runtime

COPY --from=go-builder /src/pahlevan-agent /usr/local/bin/pahlevan-agent
COPY --from=go-builder /src/pahlevan-operator /usr/local/bin/pahlevan-operator
COPY --from=go-builder /src/pahlevan /usr/local/bin/pahlevan
# Compiled eBPF objects (also embedded in the agent binary via bpf2go).
COPY --from=go-builder /src/pkg/ebpf/*.o /opt/pahlevan/ebpf/

LABEL org.opencontainers.image.title="Pahlevan" \
      org.opencontainers.image.description="eBPF-powered Kubernetes runtime security" \
      org.opencontainers.image.vendor="Obsernetics" \
      org.opencontainers.image.licenses="Apache-2.0" \
      org.opencontainers.image.source="https://github.com/obsernetics/pahlevan" \
      org.opencontainers.image.documentation="https://github.com/obsernetics/pahlevan/blob/main/README.md"

EXPOSE 8080
# Default to the operator; the agent DaemonSet overrides command to pahlevan-agent.
ENTRYPOINT ["/usr/local/bin/pahlevan-operator"]
