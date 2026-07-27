VERSION := $(shell git describe --tags --always --dirty)
COMMIT  := $(shell git rev-parse HEAD)
TAG     := $(shell git describe --exact-match --tags HEAD 2>/dev/null)
DIRTY   := $(shell test -n "$$(git status --porcelain)" && echo true || echo false)
LDFLAGS := -X github.com/bawdo/jellyfish/internal/version.Version=$(VERSION) \
           -X github.com/bawdo/jellyfish/internal/version.Commit=$(COMMIT) \
           -X github.com/bawdo/jellyfish/internal/version.Tag=$(TAG) \
           -X github.com/bawdo/jellyfish/internal/version.Dirty=$(DIRTY)

.DEFAULT_GOAL := build

help: ## List the available targets
	@grep -hE '^[a-zA-Z0-9_-]+:.*?## ' $(MAKEFILE_LIST) \
		| sort \
		| awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2}'

build: ## Build ./bin/jellyfish with version ldflags
	go build -ldflags "$(LDFLAGS)" -o bin/jellyfish .

install: ## Install the binary into GOBIN with version ldflags
	go install -ldflags "$(LDFLAGS)" .

test: ## Run the full test suite
	go test ./...

lint: ## Run golangci-lint
	golangci-lint run

pre-ci: ## Run the full local CI validation suite
	./scripts/pre-ci-check.sh

pre-ci-fix: ## Run pre-ci, auto-formatting with gofmt first
	./scripts/pre-ci-check.sh --fix gofmt

.PHONY: help build install test lint pre-ci pre-ci-fix
