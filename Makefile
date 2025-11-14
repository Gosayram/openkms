.PHONY: help build test fmt lint vet clean run deps tidy update install-tools check-all fix-all tag push-tag release

# Version information
VERSION_FILE := .release-version
VERSION := $(shell if [ -f $(VERSION_FILE) ]; then cat $(VERSION_FILE) | tr -d '[:space:]'; else echo "dev"; fi)
COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
DATE := $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

# LDFLAGS for version injection
LDFLAGS := -X 'github.com/Gosayram/openkms/internal/version.Version=$(VERSION)' \
           -X 'github.com/Gosayram/openkms/internal/version.Commit=$(COMMIT)' \
           -X 'github.com/Gosayram/openkms/internal/version.Date=$(DATE)' \
           -s -w

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	@echo "Building openkms-server (version: $(VERSION), commit: $(COMMIT))..."
	@go build -ldflags "$(LDFLAGS)" -trimpath -o bin/openkms-server ./cmd/openkms-server
	@echo "Building openkms-cli (version: $(VERSION), commit: $(COMMIT))..."
	@go build -ldflags "$(LDFLAGS)" -trimpath -o bin/openkms-cli ./cmd/openkms-cli

test: ## Run tests
	go test -v -race -coverprofile=coverage.out ./...

test-coverage: test ## Run tests with coverage report
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

fmt: ## Format code
	go fmt ./...
	@if command -v goimports > /dev/null; then \
		goimports -w .; \
	else \
		echo "goimports not found, install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi

lint: ## Run linter
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
	else \
		echo "golangci-lint not found, install with: make install-tools"; \
	fi

vet: ## Run go vet
	go vet ./...

clean: ## Clean build artifacts
	rm -rf bin/ coverage.out coverage.html

run: build ## Run the server
	./bin/openkms-server

deps: ## Download dependencies
	go mod download

tidy: ## Tidy dependencies
	go mod tidy

update: ## Update all dependencies to latest versions and create commit
	@./hack/update-deps.sh

check-all: copyright-check ## Run all checks (copyright, format, goimports, lint)
	@echo "Checking code formatting (gofmt)..."
	@if gofmt -l . | grep -q .; then \
		echo "❌ gofmt found issues. Run 'make fix-all' to fix."; \
		gofmt -l .; \
		exit 1; \
	fi
	@echo "✅ gofmt check passed"
	@if command -v goimports > /dev/null; then \
		echo "Running goimports check..."; \
		if goimports -d . | grep -q .; then \
			echo "❌ goimports found issues. Run 'make fix-all' to fix."; \
			exit 1; \
		fi; \
		echo "✅ goimports check passed"; \
	else \
		echo "⚠️  goimports not found, skipping check. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi
	@echo "Running linter (golangci-lint)..."
	@if command -v golangci-lint > /dev/null; then \
		golangci-lint run; \
		if [ $$? -eq 0 ]; then \
			echo "✅ linter check passed"; \
		else \
			echo "❌ linter found issues."; \
			exit 1; \
		fi; \
	else \
		echo "⚠️  golangci-lint not found, skipping check. Install with: make install-tools"; \
	fi

fix-all: copyright-add fmt ## Fix all issues (copyright, format, goimports)
	@if command -v goimports > /dev/null; then \
		echo "Running goimports to fix imports..."; \
		goimports -w .; \
		echo "✅ goimports fixes applied"; \
	else \
		echo "⚠️  goimports not found, skipping. Install with: go install golang.org/x/tools/cmd/goimports@latest"; \
	fi
	@echo "✅ All fixes applied"

check: fmt vet lint test ## Run all checks (format, vet, lint, test)

install-tools: ## Install development tools
	@echo "Installing development tools..."
	@go install golang.org/x/tools/cmd/goimports@latest
	@go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@latest
	@echo "Tools installed successfully"

copyright-check: ## Check copyright headers
	@./hack/check-copyright.sh

copyright-add: ## Add copyright headers to files
	@./hack/add-copyright.sh

copyright-update: ## Update copyright year
	@./hack/update-copyright.sh

update-version: ## Update version in .release-version based on current phase in .arch-plan-docs.md
	@./hack/update-version.sh

changelog: ## Generate CHANGELOG.md from git commits
	@./hack/generate-changelog.sh

tag: ## Create git tag from .release-version
	@if [ ! -f $(VERSION_FILE) ]; then \
		echo "Error: $(VERSION_FILE) not found"; \
		exit 1; \
	fi
	@TAG_VERSION="v$(VERSION)"; \
	if git rev-parse "$$TAG_VERSION" >/dev/null 2>&1; then \
		echo "Error: Tag $$TAG_VERSION already exists"; \
		exit 1; \
	fi; \
	echo "Creating tag $$TAG_VERSION..."; \
	git tag -a "$$TAG_VERSION" -m "Release $$TAG_VERSION"; \
	echo "✅ Tag $$TAG_VERSION created"

push-tag: tag ## Create tag and push to remote repository
	@TAG_VERSION="v$(VERSION)"; \
	CURRENT_BRANCH=$$(git branch --show-current 2>/dev/null || echo ""); \
	REMOTE=$$(git config branch.$$CURRENT_BRANCH.remote 2>/dev/null || echo "origin"); \
	if [ -z "$$REMOTE" ] || [ "$$REMOTE" = "" ]; then \
		REMOTE="origin"; \
	fi; \
	echo "Pushing tag $$TAG_VERSION to $$REMOTE..."; \
	git push $$REMOTE "$$TAG_VERSION"; \
	echo "✅ Tag $$TAG_VERSION pushed to $$REMOTE"

release: changelog push-tag ## Create release: update changelog, create tag and push
	@echo "✅ Release $(VERSION) created and pushed"

