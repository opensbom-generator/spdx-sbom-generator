# SPDX-License-Identifier: Apache-2.0

# It's necessary to set this because some environments don't link sh -> bash.
SHELL := /usr/bin/env bash
VERSION=$(shell cat version.txt)
PKG_LIST := $(shell go list ./... | grep -v mock)
ldflags='-X "main.version=$(VERSION)"'
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
	@GO111MODULE=on GOFLAGS=-mod=vendor go mod vendor
	@GO111MODULE=on GOFLAGS=-mod=vendor go mod tidy

.PHONY: generator
generate: mod
	@echo "Running cli on version $(VERSION)"
	@GO111MODULE=on GLFLAGs=-mod-vendor go run cmd/generator/generator.go $(ARGS)

.PHONY: build
build: mod
	@echo "Building spdx-sbom-generator for Linux Intel/AMD 64-bit version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=linux go build -ldflags $(ldflags) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator
	
.PHONY: build-ppc64le
build-ppc64le: mod
	@echo "Building spdx-sbom-generator for Linux ppc64le version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=linux GOARCH=ppc64le go build -ldflags $(ldflags) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-s390x
build-s390x: mod
	@echo "Building spdx-sbom-generator for Linux s390x version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=linux GOARCH=s390x go build -ldflags $(ldflags) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-mac
build-mac: mod
	@echo "Building spdx-sbom-generator for Mac Intel/AMD 64-bit version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=darwin GOARCH=amd64 go build -ldflags $(ldflags) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-mac-arm64
build-mac-arm64: mod
	@echo "Building spdx-sbom-generator for Mac ARM 64-bit version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=darwin GOARCH=arm64 go build -ldflags $(ldflags) -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-win
build-win: mod
	@echo "Building spdx-sbom-generator for Windows Intel/AMD 64-bit version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=windows GOARCH=amd64 go build -ldflags $(ldflags) -o bin/spdx-sbom-generator.exe cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator.exe

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
