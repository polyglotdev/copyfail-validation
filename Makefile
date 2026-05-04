SHELL := /usr/bin/env bash
.SHELLFLAGS := -eu -o pipefail -c
.DEFAULT_GOAL := help

GO ?= go
GOLANGCI_LINT ?= golangci-lint
PKG := ./...

.PHONY: help
help: ## List available targets
	@awk 'BEGIN {FS = ":.*##"} /^[a-zA-Z_-]+:.*##/ { printf "  \033[36m%-20s\033[0m %s\n", $$1, $$2 }' $(MAKEFILE_LIST)

.PHONY: tidy
tidy: ## Run go mod tidy
	$(GO) mod tidy

.PHONY: lint
lint: ## Run golangci-lint
	$(GOLANGCI_LINT) run $(PKG)

.PHONY: test
test: ## Run unit tests with race detector
	$(GO) test -race -count=1 $(PKG)

.PHONY: test-integration
test-integration: ## Run integration tests (build tag: integration)
	$(GO) test -race -count=1 -tags=integration $(PKG)

.PHONY: cover
cover: ## Run tests and emit coverage report
	$(GO) test -race -count=1 -coverprofile=cover.out -covermode=atomic $(PKG)
	$(GO) tool cover -func=cover.out | tail -1

.PHONY: cover-html
cover-html: cover ## Open the HTML coverage report in a browser
	$(GO) tool cover -html=cover.out

.PHONY: vuln
vuln: ## Run govulncheck
	$(GO) run golang.org/x/vuln/cmd/govulncheck@latest $(PKG)

.PHONY: fuzz-kernelmod
fuzz-kernelmod: ## Run kernelmod fuzzers for 30s each
	$(GO) test -fuzz=FuzzParseProcModules -fuzztime=30s ./internal/kernelmod
	$(GO) test -fuzz=FuzzParseModprobeConf -fuzztime=30s ./internal/kernelmod

.PHONY: build
build: ## Build the CLI binary into ./dist
	mkdir -p dist
	CGO_ENABLED=0 $(GO) build -trimpath -ldflags "-s -w" -o dist/copyfail-validate ./cmd/copyfail-validate

.PHONY: clean
clean: ## Remove build artifacts and coverage files
	rm -rf dist cover.out cover.html
