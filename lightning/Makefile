.PHONY: all build test test-unit test-integration test-docker-up test-docker-down test-full clean

# Build the binary
build:
	go build -o lightning ./cmd/lightning

# Run all tests
test: test-unit

# Run unit tests
test-unit:
	go test -v -short ./...

# Start Docker test infrastructure
test-docker-up:
	docker compose -f docker-compose.test.yml up -d
	@echo "Waiting for services to be ready..."
	@sleep 10

# Stop Docker test infrastructure
test-docker-down:
	docker compose -f docker-compose.test.yml down -v

# Run integration tests (requires Docker)
test-integration: test-docker-up
	@echo "Running integration tests..."
	go test -v ./test/integration/... -timeout 30m || true
	@$(MAKE) test-docker-down

# Run full test suite
test-full: build test-unit test-integration

# Clean build artifacts
clean:
	rm -f lightning
	go clean

# Install dependencies
deps:
	go mod download
	go get github.com/stretchr/testify

# Run linter
lint:
	golangci-lint run ./...

# Format code
fmt:
	go fmt ./...

# Show test coverage
coverage:
	go test -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html
	@echo "Coverage report generated: coverage.html"

# Run benchmarks
bench:
	go test -bench=. -benchmem ./...

# Docker logs
test-logs:
	docker compose -f docker-compose.test.yml logs -f

# Docker rebuild
test-rebuild:
	docker compose -f docker-compose.test.yml build --no-cache

# Quick test with public servers only
test-quick:
	go test -v ./test/integration/... -run "TestDoTScanner/Cloudflare|TestDoHScanner/Cloudflare|TestFalsePositive"

help:
	@echo "Available targets:"
	@echo "  build            - Build the DNS scanner binary"
	@echo "  test             - Run unit tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests with Docker"
	@echo "  test-docker-up   - Start Docker test infrastructure"
	@echo "  test-docker-down - Stop Docker test infrastructure"
	@echo "  test-full        - Run complete test suite"
	@echo "  test-quick       - Run quick tests against public servers"
	@echo "  test-logs        - Show Docker container logs"
	@echo "  test-rebuild     - Rebuild Docker containers from scratch"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Install dependencies"
	@echo "  lint             - Run linter"
	@echo "  fmt              - Format code"
	@echo "  coverage         - Generate test coverage report"
	@echo "  bench            - Run benchmarks"
