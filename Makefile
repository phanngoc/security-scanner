# Security Scanner Makefile

# Variables
BINARY_NAME=security-scanner
VERSION=$(shell git describe --tags --always --dirty)
BUILD_TIME=$(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS=-ldflags "-X main.Version=$(VERSION) -X main.BuildTime=$(BUILD_TIME)"

# Default target
.PHONY: all
all: clean build test

# Build the binary
.PHONY: build
build:
	@echo "Building $(BINARY_NAME)..."
	go build $(LDFLAGS) -o bin/$(BINARY_NAME) main.go

# Build for multiple platforms
.PHONY: build-all
build-all: clean
	@echo "Building for multiple platforms..."
	GOOS=linux GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-linux-amd64 main.go
	GOOS=darwin GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-amd64 main.go
	GOOS=darwin GOARCH=arm64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-darwin-arm64 main.go
	GOOS=windows GOARCH=amd64 go build $(LDFLAGS) -o bin/$(BINARY_NAME)-windows-amd64.exe main.go

# Run tests
.PHONY: test
test:
	@echo "Running tests..."
	go test -v ./...

# Run tests with coverage
.PHONY: test-coverage
test-coverage:
	@echo "Running tests with coverage..."
	go test -v -coverprofile=coverage.out ./...
	go tool cover -html=coverage.out -o coverage.html

# Run benchmark tests
.PHONY: benchmark
benchmark:
	@echo "Running benchmarks..."
	go test -bench=. -benchmem ./...

# Lint the code
.PHONY: lint
lint:
	@echo "Running linter..."
	golangci-lint run

# Format the code
.PHONY: fmt
fmt:
	@echo "Formatting code..."
	go fmt ./...

# Vet the code
.PHONY: vet
vet:
	@echo "Vetting code..."
	go vet ./...

# Clean build artifacts
.PHONY: clean
clean:
	@echo "Cleaning..."
	rm -rf bin/
	rm -f coverage.out coverage.html

# Install dependencies
.PHONY: deps
deps:
	@echo "Installing dependencies..."
	go mod download
	go mod tidy

# Install the binary
.PHONY: install
install: build
	@echo "Installing $(BINARY_NAME)..."
	cp bin/$(BINARY_NAME) $(GOPATH)/bin/

# Run security scanner on itself
.PHONY: self-scan
self-scan: build
	@echo "Running security scanner on itself..."
	./bin/$(BINARY_NAME) --format text .

# Generate documentation
.PHONY: docs
docs:
	@echo "Generating documentation..."
	go run main.go --help > docs/cli-help.txt

# Create release package
.PHONY: release
release: build-all test
	@echo "Creating release package..."
	mkdir -p release
	tar -czf release/$(BINARY_NAME)-$(VERSION)-linux-amd64.tar.gz -C bin $(BINARY_NAME)-linux-amd64 -C .. README.md LICENSE
	tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-amd64.tar.gz -C bin $(BINARY_NAME)-darwin-amd64 -C .. README.md LICENSE
	tar -czf release/$(BINARY_NAME)-$(VERSION)-darwin-arm64.tar.gz -C bin $(BINARY_NAME)-darwin-arm64 -C .. README.md LICENSE
	zip -j release/$(BINARY_NAME)-$(VERSION)-windows-amd64.zip bin/$(BINARY_NAME)-windows-amd64.exe README.md LICENSE

# Docker build
.PHONY: docker-build
docker-build:
	@echo "Building Docker image..."
	docker build -t $(BINARY_NAME):$(VERSION) .
	docker tag $(BINARY_NAME):$(VERSION) $(BINARY_NAME):latest

# Docker run
.PHONY: docker-run
docker-run:
	@echo "Running Docker container..."
	docker run --rm -v $(PWD):/workspace $(BINARY_NAME):latest /workspace

# Show help
.PHONY: help
help:
	@echo "Available targets:"
	@echo "  build         - Build the binary"
	@echo "  build-all     - Build for multiple platforms"
	@echo "  test          - Run tests"
	@echo "  test-coverage - Run tests with coverage"
	@echo "  benchmark     - Run benchmark tests"
	@echo "  lint          - Run linter"
	@echo "  fmt           - Format code"
	@echo "  vet           - Vet code"
	@echo "  clean         - Clean build artifacts"
	@echo "  deps          - Install dependencies"
	@echo "  install       - Install binary"
	@echo "  self-scan     - Run scanner on itself"
	@echo "  docs          - Generate documentation"
	@echo "  release       - Create release package"
	@echo "  docker-build  - Build Docker image"
	@echo "  docker-run    - Run Docker container"
	@echo "  help          - Show this help"
