IMG_REGISTRY ?= ghcr.io
IMG_REPOSITORY ?= netbirdio/netbird-kubeapi-proxy
IMG_TAG ?= dev
IMG_REF := $(IMG_REGISTRY)/$(IMG_REPOSITORY):$(IMG_TAG)

VERSION ?= $(IMG_TAG)
# A leading "v" is dropped and "_", valid in image tags but not in build metadata,
# becomes "-".
PROXY_VERSION := $(subst _,-,$(patsubst v%,%,$(VERSION)))
NETBIRD_VERSION := $(patsubst v%,%,$(shell go list -m -f '{{.Version}}' github.com/netbirdio/netbird))
# The NetBird release must stay the semver core: Management gates features on it
# with >= checks, and build metadata (after "+") is ignored by those comparisons.
REPORTED_VERSION := $(NETBIRD_VERSION)+kubeapi-proxy.$(PROXY_VERSION)

.PHONY: lint
lint:
	@golangci-lint run ./...
	@cd test/e2e && golangci-lint run --build-tags e2e ./...

.PHONY: test
test-unit:
	@go test ./... -race -coverprofile=coverage.txt

# Needs only Docker and Go: the suite starts NetBird and a Kind cluster itself.
# test/e2e/main_test.go describes the setup and the environment knobs.
.PHONY: test-e2e
test-e2e: build-image
	@cd test/e2e && IMG_REF=$(IMG_REF) go test -tags e2e ./... -v -count 1 -timeout 30m

.PHONY: build
build: bin/linux-$(shell go env GOARCH)/netbird-kubeapi-proxy

# Always rebuilt: the stamped version is not a file prerequisite, so a leftover
# binary would otherwise keep reporting an old version. The Go build cache keeps
# this cheap.
.PHONY: FORCE
FORCE:

bin/linux-%/netbird-kubeapi-proxy: FORCE
	@CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -ldflags="-w -s -X github.com/netbirdio/netbird/version.version=$(REPORTED_VERSION) -X github.com/netbirdio/netbird-kubeapi-proxy/internal/version.version=$(PROXY_VERSION)" -trimpath -o $@ main.go

.PHONY: build-image
build-image: build
	@DOCKER_BUILDKIT=1 docker build -t ${IMG_REF} .
	@echo ${IMG_REF}

.PHONY: build-image-multiarch
build-image-multiarch: bin/linux-amd64/netbird-kubeapi-proxy bin/linux-arm64/netbird-kubeapi-proxy
	@DOCKER_BUILDKIT=1 docker build --platform linux/amd64,linux/arm64 -t ${IMG_REF} .
	@echo ${IMG_REF}

deploy: build-image
	kind load docker-image ${IMG_REF}
	kustomize build manifests | kubectl apply -f -
	kubectl rollout restart deployment/netbird-kubeapi-proxy
