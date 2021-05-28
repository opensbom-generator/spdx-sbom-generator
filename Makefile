# It's necessary to set this because some environments don't link sh -> bash.
SHELL := /usr/bin/env bash
VERSION=$(shell cat version.txt)

.PHONY: help
help:           ## Show this help.
	@fgrep -h "##" $(MAKEFILE_LIST) | fgrep -v fgrep | sed -e 's/\\$$//' | sed -e 's/##//'

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
	@echo "Building spdx-sbom-generator version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=linux go build -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-mac
build-mac: mod
	@echo "Building spdx-sbom-generator version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=darwin GOARCH=amd64 go build -o bin/spdx-sbom-generator cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator

.PHONY: build-win
build-win: mod
	@echo "Building spdx-sbom-generator version:$(VERSION)"
	@GO111MODULE=on GOFLAGS=-mod=vendor GOOS=win GOARCH=amd64 go build -o bin/spdx-sbom-generator.exe cmd/generator/generator.go
	@chmod +x bin/spdx-sbom-generator.exe

.PHONY: lint
lint:
	@echo "Define linter"

.PHONY: test
test:
	@echo "IMPLEMENT TEST"
