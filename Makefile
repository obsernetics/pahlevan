# Pahlevan eBPF-based Kubernetes Security Operator Makefile
# Copyright 2025

# Variables
BINARY_NAME=pahlevan-operator
CONTAINER_NAME=pahlevan/operator
VERSION?=v1.0.0
BUILD_DIR=bin
BPF_DIR=bpf
PKG_DIR=pkg/ebpf

# Image URL to use all building/pushing image targets
IMG ?= $(CONTAINER_NAME):$(VERSION)
# ENVTEST_K8S_VERSION refers to the version of kubebuilder assets to be downloaded by envtest binary.
ENVTEST_K8S_VERSION = 1.28.0

# Go variables
GO_VERSION=1.24
GOOS?=$(shell go env GOOS)
GOARCH?=$(shell go env GOARCH)
CGO_ENABLED=1

# eBPF variables
CLANG?=clang
LLC?=llc
LLVM_STRIP?=llvm-strip
BPF_CFLAGS := -O2 -g -Wall -Werror
BPF_TARGET=bpf_target
KERNEL_VERSION?=$(shell uname -r)

# Kubernetes variables
KUBECONFIG?=~/.kube/config
NAMESPACE?=pahlevan-system

# Test variables
INTEGRATION_TEST_ARGS?=-v
UNIT_TEST_ARGS?=-v -race

# Get the currently used golang install path (in GOPATH/bin, unless GOBIN is set)
ifeq (,$(shell go env GOBIN))
GOBIN=$(shell go env GOPATH)/bin
else
GOBIN=$(shell go env GOBIN)
endif

# Setting SHELL to bash allows bash commands to be executed by recipes.
SHELL = /usr/bin/env bash -o pipefail
.SHELLFLAGS = -ec

.PHONY: all
all: build

##@ General

# The help target prints out all targets with their descriptions organized
# beneath their categories. The categories are represented by '##@' and the
# target descriptions by '##'. The awk commands is responsible for reading the
# entire set of makefiles included in this invocation, looking for lines of the
# file as xyz: ## something, and then pretty-format the target and help. Then,
# if there's a line with ##@ something, that gets pretty-printed as a category.
# More info on the usage of ANSI control characters for terminal formatting:
# https://en.wikipedia.org/wiki/ANSI_escape_code#SGR_parameters
# More info on the awk command:
# http://linuxcommand.org/lc3_adv_awk.php

.PHONY: help
help: ## Display this help.
	@awk 'BEGIN {FS = ":.*##"; printf "\nUsage:\n  make \033[36m<target>\033[0m\n"} /^[a-zA-Z_0-9-]+:.*?##/ { printf "  \033[36m%-15s\033[0m %s\n", $$1, $$2 } /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } ' $(MAKEFILE_LIST)

##@ Development

.PHONY: manifests
manifests: controller-gen ## Generate WebhookConfiguration, ClusterRole and CustomResourceDefinition objects.
	$(CONTROLLER_GEN) rbac:roleName=manager-role crd webhook paths="./..." output:crd:artifacts:config=config/crd output:rbac:artifacts:config=config/rbac

.PHONY: generate
generate: controller-gen ## Generate code containing DeepCopy, DeepCopyInto, and DeepCopyObject method implementations.
	$(CONTROLLER_GEN) object:headerFile="hack/boilerplate.go.txt" paths="./..."

.PHONY: fmt
fmt: ## Run go fmt against code.
	go fmt ./...

.PHONY: vet
vet: ## Run go vet against code.
	go vet ./...

.PHONY: test
test: manifests generate fmt vet envtest ## Run tests.
	KUBEBUILDER_ASSETS="$(shell $(ENVTEST) use $(ENVTEST_K8S_VERSION) --bin-dir $(LOCALBIN) -p path)" go test ./... -coverprofile cover.out

.PHONY: test-unit
test-unit: ## Run unit tests only
	go test -v -race -covermode=atomic -coverprofile=coverage.out ./pkg/... ./internal/... ./cmd/...

.PHONY: test-coverage
test-coverage: ## Run tests with coverage report
	@echo "Running test coverage analysis..."
	@./scripts/test-coverage.sh

.PHONY: test-integration
test-integration: ## Run integration tests
	go test -v -tags=integration ./test/integration/...

.PHONY: test-e2e
test-e2e: ## Run end-to-end tests
	go test -v -timeout=30m -tags=e2e ./test/e2e/...

.PHONY: test-benchmark
test-benchmark: ## Run benchmark tests
	go test -bench=. -benchmem ./...

.PHONY: test-all
test-all: test-unit test-integration test-e2e ## Run all tests

.PHONY: coverage-html
coverage-html: test-unit ## Generate HTML coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

.PHONY: lint
lint: golangci-lint ## Run golangci-lint linter & yamllint
	$(GOLANGCI_LINT) run

.PHONY: lint-fix
lint-fix: golangci-lint ## Run golangci-lint linter and perform fixes
	$(GOLANGCI_LINT) run --fix

##@ eBPF Development

.PHONY: ebpf-deps
ebpf-deps: ## Install eBPF development dependencies
	@echo "Installing eBPF dependencies..."
	@which clang > /dev/null || (echo "Error: clang not found. Please install LLVM/Clang" && exit 1)
	@which llc > /dev/null || (echo "Error: llc not found. Please install LLVM/Clang" && exit 1)
	@which llvm-strip > /dev/null || (echo "Error: llvm-strip not found. Please install LLVM/Clang" && exit 1)
	@echo "eBPF dependencies are installed"

.PHONY: ebpf-clean
ebpf-clean: ## Clean eBPF build artifacts
	@echo "Cleaning eBPF build artifacts..."
	rm -f $(BPF_DIR)/*.o
	rm -f $(PKG_DIR)/*_bpf*.go
	rm -f $(PKG_DIR)/*_bpf*.o

.PHONY: ebpf-compile
ebpf-compile: ebpf-deps ## Compile eBPF programs
	@echo "Compiling eBPF programs..."
	cd $(BPF_DIR) && \
	$(CLANG) $(BPF_CFLAGS) -target $(BPF_TARGET) -c syscall_monitor.c -o syscall_monitor.o && \
	$(CLANG) $(BPF_CFLAGS) -target $(BPF_TARGET) -c network_monitor.c -o network_monitor.o && \
	$(CLANG) $(BPF_CFLAGS) -target $(BPF_TARGET) -c file_monitor.c -o file_monitor.o
	@echo "eBPF programs compiled successfully"

.PHONY: ebpf-generate
ebpf-generate: ebpf-compile ## Generate Go bindings for eBPF programs
	@echo "Generating Go bindings for eBPF programs..."
	@which bpf2go > /dev/null || go install github.com/cilium/ebpf/cmd/bpf2go@latest
	cd $(PKG_DIR) && go generate -x ./...
	@echo "Go bindings generated successfully"

.PHONY: ebpf-build
ebpf-build: ebpf-generate ## Build eBPF programs and generate bindings
	@echo "eBPF build completed"

.PHONY: ebpf-verify
ebpf-verify: ebpf-build ## Verify eBPF programs
	@echo "Verifying eBPF programs..."
	file $(BPF_DIR)/*.o
	@echo "eBPF programs verified"

.PHONY: test-ebpf
test-ebpf: ebpf-build ## Test eBPF programs
	@echo "Testing eBPF programs..."
	@echo "eBPF tests completed"

##@ Build

.PHONY: build
build: manifests generate fmt vet ebpf-build ## Build manager binary.
	go build -o bin/manager cmd/operator/main.go

.PHONY: run
run: manifests generate fmt vet ## Run a controller from your host.
	go run ./cmd/operator/main.go

# If you wish built the manager image targeting other platforms you can use the --platform flag.
# (i.e. docker build --platform linux/arm64 ). However, you must enable docker buildKit for it.
# More info: https://docs.docker.com/develop/dev-best-practices/
.PHONY: docker-build
docker-build: ## Build docker image with the manager.
	docker build -t ${IMG} .

.PHONY: docker-push
docker-push: ## Push docker image with the manager.
	docker push ${IMG}

# PLATFORMS defines the target platforms for  the manager image be build to provide support to multiple
# architectures. (i.e. make docker-buildx IMG=myregistry/mypoperator:0.0.1). To use this option you need to:
# - able to use docker buildx . More info: https://docs.docker.com/build/buildx/
# - have a multi-arch builder. More info: https://docs.docker.com/build/building/multi-platform/
# - be able to push the image for your registry (i.e. if you do not inform a valid value via IMG=<myregistry/image:<tag>> then the export will fail)
# To properly provided solutions that supports more than one platform you should use this option.
PLATFORMS ?= linux/arm64,linux/amd64,linux/s390x,linux/ppc64le
.PHONY: docker-buildx
docker-buildx: ## Build and push docker image for the manager for cross-platform support
	# copy existing Dockerfile and insert --platform=${BUILDPLATFORM} into Dockerfile.cross, and preserve the original Dockerfile
	sed -e '1 s/\(^FROM\)/FROM --platform=\$$\{BUILDPLATFORM\}/; t' -e ' 1,// s//FROM --platform=\$$\{BUILDPLATFORM\}/' Dockerfile > Dockerfile.cross
	- docker buildx create --name project-v3-builder
	docker buildx use project-v3-builder
	- docker buildx build --push --platform=$(PLATFORMS) --tag ${IMG} -f Dockerfile.cross .
	- docker buildx rm project-v3-builder
	rm Dockerfile.cross

##@ Deployment

ifndef ignore-not-found
  ignore-not-found = false
endif

.PHONY: install
install: manifests kustomize ## Install CRDs into the K8s cluster specified in ~/.kube/config.
	$(KUSTOMIZE) build config/crd | kubectl apply -f -

.PHONY: install-all
install-all: manifests kustomize ## Install complete Pahlevan operator (CRDs, RBAC, Operator)
	@echo "Installing Pahlevan eBPF Security Operator..."
	kubectl create namespace pahlevan-system --dry-run=client -o yaml | kubectl apply -f -
	$(KUSTOMIZE) build config/default | kubectl apply -f -
	@echo "Waiting for operator to be ready..."
	kubectl wait --for=condition=ready pod -l app.kubernetes.io/name=pahlevan -n pahlevan-system --timeout=300s
	@echo "✅ Pahlevan operator installed successfully!"
	@echo "📋 Next steps:"
	@echo "  1. Create a PahlevanPolicy: kubectl apply -f examples/quickstart/simple-policy.yaml"
	@echo "  2. Check status: kubectl get pahlevanpolicy"
	@echo "  3. View logs: kubectl logs -n pahlevan-system deployment/pahlevan-controller-manager"

.PHONY: quick-start
quick-start: install-all ## Complete quick start installation with example
	@echo "🚀 Setting up quick start example..."
	kubectl apply -f examples/quickstart/simple-policy.yaml
	@echo "✅ Example policy applied!"
	@echo "📖 View the getting started guide: docs/USAGE.md"

.PHONY: uninstall
uninstall: manifests kustomize ## Uninstall CRDs from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/crd | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

.PHONY: deploy
deploy: manifests kustomize ## Deploy controller to the K8s cluster specified in ~/.kube/config.
	cd config/manager && $(KUSTOMIZE) edit set image controller=${IMG}
	$(KUSTOMIZE) build config/default | kubectl apply -f -

.PHONY: undeploy
undeploy: ## Undeploy controller from the K8s cluster specified in ~/.kube/config. Call with ignore-not-found=true to ignore resource not found errors during deletion.
	$(KUSTOMIZE) build config/default | kubectl delete --ignore-not-found=$(ignore-not-found) -f -

##@ Build Dependencies

## Location to install dependencies to
LOCALBIN ?= $(shell pwd)/bin
$(LOCALBIN):
	mkdir -p $(LOCALBIN)

## Tool Binaries
KUSTOMIZE ?= $(LOCALBIN)/kustomize
CONTROLLER_GEN ?= $(LOCALBIN)/controller-gen
ENVTEST ?= $(LOCALBIN)/setup-envtest
GOLANGCI_LINT = $(LOCALBIN)/golangci-lint

## Tool Versions
KUSTOMIZE_VERSION ?= v5.0.4
CONTROLLER_TOOLS_VERSION ?= v0.13.0
GOLANGCI_LINT_VERSION ?= v1.54.2

KUSTOMIZE_INSTALL_SCRIPT ?= "https://raw.githubusercontent.com/kubernetes-sigs/kustomize/master/hack/install_kustomize.sh"
.PHONY: kustomize
kustomize: $(KUSTOMIZE) ## Download kustomize locally if necessary. If wrong version is installed, it will be removed before downloading.
$(KUSTOMIZE): $(LOCALBIN)
	@if test -x $(LOCALBIN)/kustomize && ! $(LOCALBIN)/kustomize version | grep -q $(KUSTOMIZE_VERSION); then \
		echo "$(LOCALBIN)/kustomize version is not expected $(KUSTOMIZE_VERSION). Removing it before installing."; \
		rm -rf $(LOCALBIN)/kustomize; \
	fi
	test -s $(LOCALBIN)/kustomize || { curl -Ss $(KUSTOMIZE_INSTALL_SCRIPT) | bash -s -- $(subst v,,$(KUSTOMIZE_VERSION)) $(LOCALBIN); }

.PHONY: controller-gen
controller-gen: $(CONTROLLER_GEN) ## Download controller-gen locally if necessary. If wrong version is installed, it will be overwritten.
$(CONTROLLER_GEN): $(LOCALBIN)
	test -s $(LOCALBIN)/controller-gen && $(LOCALBIN)/controller-gen --version | grep -q $(CONTROLLER_TOOLS_VERSION) || \
	GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-tools/cmd/controller-gen@$(CONTROLLER_TOOLS_VERSION)

.PHONY: envtest
envtest: $(ENVTEST) ## Download envtest-setup locally if necessary.
$(ENVTEST): $(LOCALBIN)
	test -s $(LOCALBIN)/setup-envtest || GOBIN=$(LOCALBIN) go install sigs.k8s.io/controller-runtime/tools/setup-envtest@latest

.PHONY: golangci-lint
golangci-lint: $(GOLANGCI_LINT) ## Download golangci-lint locally if necessary.
$(GOLANGCI_LINT): $(LOCALBIN)
	test -s $(LOCALBIN)/golangci-lint && $(LOCALBIN)/golangci-lint --version | grep -q $(GOLANGCI_LINT_VERSION) || \
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s -- -b $(LOCALBIN) $(GOLANGCI_LINT_VERSION)