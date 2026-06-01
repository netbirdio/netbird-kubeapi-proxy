IMG_REGISTRY ?= ghcr.io
IMG_REPOSITORY ?= netbirdio/netbird-kubeapi-proxy
IMG_TAG ?= dev
IMG_REF := $(IMG_REGISTRY)/$(IMG_REPOSITORY):$(IMG_TAG)

.PHONY: lint
lint:
	@golangci-lint run ./...

.PHONY: test
test-unit:
	@go test ./... -race -coverprofile=coverage.txt

.PHONY: build
build: bin/linux-$(shell go env GOARCH)/netbird-kubeapi-proxy

bin/linux-%/netbird-kubeapi-proxy: $(shell find internal) main.go go.mod go.sum
	@CGO_ENABLED=0 GOOS=linux GOARCH=$* go build -ldflags="-w -s" -trimpath -o $@ main.go

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
