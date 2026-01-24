.PHONY: all build build-release build-pgo pgo-profile pgo-clean test test-unit test-integration test-docker-up test-docker-down test-full clean deps lint fmt coverage bench help

VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo "dev")
COMMIT ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo "none")
DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")

LDFLAGS_RELEASE := -s -w -X main.version=$(VERSION) -X main.commit=$(COMMIT) -X main.date=$(DATE)
PGO_PROFILE := default.pgo

# Build the binary
build:
	go build -o lightning ./cmd/lightning

# Build optimized release binary
build-release:
	go build -ldflags="$(LDFLAGS_RELEASE)" -trimpath -o lightning ./cmd/lightning

# Build with Profile-Guided Optimization (Go 1.21+)
# Uses default.pgo if present, falls back to standard build
# PGO typically provides 3-7% performance improvement for I/O-bound applications
build-pgo:
	@if [ -f $(PGO_PROFILE) ]; then \
		echo "Building with PGO profile: $(PGO_PROFILE)"; \
		go build -pgo=$(PGO_PROFILE) -ldflags="$(LDFLAGS_RELEASE)" -trimpath -o lightning ./cmd/lightning; \
	else \
		echo "No PGO profile found, building without PGO"; \
		go build -ldflags="$(LDFLAGS_RELEASE)" -trimpath -o lightning ./cmd/lightning; \
	fi

# Collect CPU profile for PGO optimization
# Run representative workload to capture hot paths
# Usage: make pgo-profile TARGETS="8.8.8.0/24 1.1.1.0/24"
TARGETS ?= 8.8.8.0/28 1.1.1.0/28
pgo-profile: build
	@echo "Collecting CPU profile with targets: $(TARGETS)"
	@mkdir -p profiles
	./lightning $(TARGETS) -w 50 -r 500 -o /dev/null 2>/dev/null &
	@PID=$$!; \
	sleep 2; \
	go tool pprof -proto -output=profiles/cpu.pprof http://localhost:6060/debug/pprof/profile?seconds=30 2>/dev/null || \
	(echo "Note: pprof endpoint not available, using test-based profiling"; \
	go test -cpuprofile=profiles/cpu.pprof -bench=. -benchtime=10s ./... 2>/dev/null); \
	kill $$PID 2>/dev/null || true
	@if [ -f profiles/cpu.pprof ]; then \
		go tool pprof -proto profiles/cpu.pprof > $(PGO_PROFILE) 2>/dev/null && \
		echo "PGO profile created: $(PGO_PROFILE)" || \
		echo "Note: Could not create PGO profile"; \
	fi

# Clean PGO profiles
pgo-clean:
	rm -f $(PGO_PROFILE) profiles/*.pprof
	rm -rf profiles

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
	@echo ""
	@echo "Build:"
	@echo "  build            - Build the binary (with debug symbols)"
	@echo "  build-release    - Build optimized release binary (stripped, with version info)"
	@echo "  build-pgo        - Build with Profile-Guided Optimization (3-7% faster)"
	@echo ""
	@echo "PGO (Profile-Guided Optimization):"
	@echo "  pgo-profile      - Collect CPU profile for PGO (run representative workload)"
	@echo "  pgo-clean        - Remove PGO profiles"
	@echo ""
	@echo "Testing:"
	@echo "  test             - Run unit tests"
	@echo "  test-unit        - Run unit tests only"
	@echo "  test-integration - Run integration tests with Docker"
	@echo "  test-docker-up   - Start Docker test infrastructure"
	@echo "  test-docker-down - Stop Docker test infrastructure"
	@echo "  test-full        - Run complete test suite"
	@echo "  test-quick       - Run quick tests against public servers"
	@echo "  test-logs        - Show Docker container logs"
	@echo "  test-rebuild     - Rebuild Docker containers from scratch"
	@echo ""
	@echo "Development:"
	@echo "  clean            - Clean build artifacts"
	@echo "  deps             - Install dependencies"
	@echo "  lint             - Run linter"
	@echo "  fmt              - Format code"
	@echo "  coverage         - Generate test coverage report"
	@echo "  bench            - Run benchmarks"
