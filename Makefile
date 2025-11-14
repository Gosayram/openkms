.PHONY: help build test fmt lint vet clean run deps tidy update install-tools check-all fix-all

help: ## Show this help message
	@echo 'Usage: make [target]'
	@echo ''
	@echo 'Available targets:'
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "  %-15s %s\n", $$1, $$2}' $(MAKEFILE_LIST)

build: ## Build the application
	@echo "Building openkms-server..."
	@go build -o bin/openkms-server ./cmd/openkms-server
	@echo "Building openkms-cli..."
	@go build -o bin/openkms-cli ./cmd/openkms-cli

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

update: ## Update all dependencies to latest versions
	@echo "Updating dependencies..."
	go get -u ./...
	go mod tidy
	@echo "Dependencies updated"

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

