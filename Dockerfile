# syntax=docker/dockerfile:1

##################################################
# Build Stage: Go application (static, no cgo)
##################################################
FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS go-builder

# ca-certificates is deliberately not here: golang:alpine already ships
# /etc/ssl/certs/ca-certificates.crt, and asking apk for it was a package
# index fetch for a file that was already on disk. git stays - the module
# proxy covers everything in go.sum today, but a replace directive pointing at
# a VCS would fail at `go mod download` with a confusing error rather than a
# missing-tool one.
RUN apk add --no-cache git

WORKDIR /src

# Cache modules first.
COPY go.mod go.sum ./
RUN go mod download && go mod verify

# Only the four directories the three binaries import, rather than `COPY . .`.
# With the whole repo in one layer, editing the README, a Helm chart, a
# manifest or a workflow invalidated the compile below - and CI builds two
# platforms, so it paid for that twice. Separate COPY lines per directory so a
# change under pkg/ does not invalidate the api/ layer either.
#
# If a new top-level Go directory appears, the build fails here with an
# unresolved import rather than silently shipping a stale binary.
COPY api/ ./api/
COPY internal/ ./internal/
COPY pkg/ ./pkg/
COPY cmd/ ./cmd/

# eBPF Go bindings (*_bpfel.go / *_bpfeb.go) and their embedded objects are
# committed, so no clang/bpf2go codegen is needed here. Regenerate out-of-band
# with `make ebpf` on a Linux host with clang + libbpf-dev.
ARG VERSION=dev
ARG COMMIT=unknown
ARG DATE=unknown

# Cross-compile to the target arch from the native builder rather than running
# the toolchain under QEMU. Go needs no cross toolchain with CGO off, and
# bpf2go emits per-arch BPF objects, so GOARCH selects the right ones.
ARG TARGETARCH

# cilium/ebpf is pure Go (no cgo needed to load eBPF), so build static binaries.
# Three binaries ship in one image; the DaemonSet/Deployment pick which to run.
#
# One `go build` for all three, not three. They share almost their whole
# dependency graph, and three invocations made the toolchain load and
# type-check that graph three times and then link the binaries one after
# another. One invocation loads it once and links the three concurrently.
RUN mkdir -p /out && CGO_ENABLED=0 GOOS=linux GOARCH=${TARGETARCH} go build \
    -ldflags="-w -s -X main.version=${VERSION} -X main.gitCommit=${COMMIT} -X main.buildDate=${DATE}" \
    -o /out/ ./cmd/pahlevan-agent ./cmd/pahlevan-operator ./cmd/pahlevan

##################################################
# Runtime Stage - distroless (the default build target)
##################################################
# Plain distroless base (not :nonroot): the agent DaemonSet must run privileged
# for eBPF, while the operator Deployment sets runAsNonRoot itself - the effective
# user is chosen per-workload via securityContext.
FROM gcr.io/distroless/base-debian12 AS runtime

COPY --from=go-builder /out/pahlevan-agent /usr/local/bin/pahlevan-agent
COPY --from=go-builder /out/pahlevan-operator /usr/local/bin/pahlevan-operator
COPY --from=go-builder /out/pahlevan /usr/local/bin/pahlevan
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
