# SPDX-License-Identifier: Apache-2.0

# It's necessary to set this because some environments don't link sh -> bash.
SHELL := /usr/bin/env bash
BUILD_TIME=$(shell sh -c 'date +%FT%T%z')
VERSION := $(shell sh -c 'git describe --always --tags')
BRANCH := $(shell sh -c 'git rev-parse --abbrev-ref HEAD')
COMMIT := $(shell sh -c 'git rev-parse --short HEAD')
GO_FILES=$(shell find . -type f -name '*.go' -not -path './vendor/*')
PKG_LIST := $(shell go list ./... | grep -v mock)
LDFLAGS=-ldflags "-s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.branch=$(BRANCH) -X main.buildDate=$(BUILD_TIME)"

ROOT_DIR:=$(shell dirname $(realpath $(firstword $(MAKEFILE_LIST))))
LINT_TOOL=$(shell go env GOPATH)/bin/golangci-lint
LINT_VERSION=v1.37.0

.PHONY: help
help:           ## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

.PHONY: setup
setup: $(LINT_TOOL)

.PHONY: mod
mod:
	@go mod download
	@go mod tidy

.PHONY: generator
generate: mod
	@echo "Running cli on version: $(VERSION)"
	@GO111MODULE=on GLFLAGs=-mod-vendor go run cmd/generator/generator.go $(ARGS)
	@GO111MODULE=on GLFLAGs=-mod-vendor go run cmd/sbomgen/sbomgen.go $(ARGS) > examples/sbom.spdx

.PHONY: build
build: mod
	@echo "Building spdx-sbom-generator for Linux Intel/AMD 64-bit version: $(VERSION)"
	env GOOS=linux GOARCH=amd64 go build $(LD_FLAGS) -o bin/spdx-sbom-generator cmd/generator/generator.go
	env GOOS=linux GOARCH=amd64 go build $(LD_FLAGS) -o bin/sbomgen cmd/sbomgen/sbomgen.go
	@chmod +x bin/spdx-sbom-generator
	@chmod +x bin/sbomgen

.PHONY: build-mac
build-mac: mod
	@echo "Building spdx-sbom-generator for Mac Intel/AMD 64-bit version: $(VERSION)"
	@env GOOS=darwin GOARCH=amd64 go build $(LD_FLAGS) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-mac-arm64
build-mac-arm64: mod
	@echo "Building spdx-sbom-generator for Mac ARM 64-bit version: $(VERSION)"
	@env GOOS=darwin GOARCH=arm64 go build $(LD_FLAGS) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-win
build-win: mod
	@echo "Building spdx-sbom-generator for Windows Intel/AMD 64-bit version: $(VERSION)"
	env GOOS=windows GOARCH=amd64 go build $(LD_FLAGS) -o bin/spdx-sbom-generator.exe cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator.exe

.PHONY: build-docker
build-docker:
	@echo "Building spdx/spdx-sbom-generator docker image version: $(VERSION)"
	docker build -t spdx/spdx-sbom-generator .

.PHONY: docker
docker:
	@echo "Building spdx/spdx-sbom-generator docker image version: $(VERSION)"
	docker build -f Dockerfile.spack -t spdx/spdx-sbom-generator .


$(LINT_TOOL):
	@echo "Installing golangci linter version $(LINT_VERSION)..."
	curl -sfL https://install.goreleaser.com/github.com/golangci/golangci-lint.sh | sh -s -- -b $(shell go env GOPATH)/bin $(LINT_VERSION)

.PHONY: go-lint
go-lint:
	echo "Running lint..." && $(LINT_TOOL) --version && $(LINT_TOOL) run --allow-parallel-runners --config=.golangci.yaml ./... && echo "Lint check passed."

.PHONY: check-headers
check-headers:
	@echo "Running license header check..."
	$(ROOT_DIR)/check-headers.sh

fmt:
	@gofmt -w -l -s $(GO_FILES)
	@goimports -w -l $(GO_FILES)

.PHONY: lint
lint: go-lint check-headers

.PHONY: test
test: prepare-test
	@echo "IMPLEMENT TEST"
	@go test -v $(PKG_LIST)

.PHONY: prepare-test
prepare-test:
	@cd pkg/modules/npm/test && npm install
	@cd pkg/modules/yarn/test && yarn install
	@cd pkg/modules/swift/test && swift build
