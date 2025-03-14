# Makefile for Sultry TLS proxy
#
# This Makefile supports building both the original and modular versions of Sultry
# The default targets build both, but you can choose which one you want

.PHONY: all build build-original build-modular clean run-client run-server run-modular-client run-modular-server test

GO = go
GO_BUILD = $(GO) build
GO_CLEAN = $(GO) clean
GO_TEST = $(GO) test
GO_VET = $(GO) vet
GO_FMT = $(GO) fmt

# Main build targets
all: build

build: build-original build-modular

# Build the original monolithic version
build-original:
	@echo "Building original version..."
	$(GO_BUILD) -o bin/sultry

# Build the modular version
build-modular:
	@echo "Building modular version..."
	$(GO_BUILD) -o bin/sultry-mod ./cmd/minimal

# Clean up binaries
clean:
	@echo "Cleaning up..."
	$(GO_CLEAN)
	rm -f bin/sultry bin/sultry-mod

# Format code
fmt:
	@echo "Formatting code..."
	$(GO_FMT) ./...

# Run tests
test:
	@echo "Running tests..."
	$(GO_TEST) -v ./...

# Vet code
vet:
	@echo "Vetting code..."
	$(GO_VET) ./...

# Run the original client
run-client:
	@echo "Running original client..."
	./bin/sultry -mode client

# Run the original server
run-server:
	@echo "Running original server..."
	./bin/sultry -mode server

# Run the modular client
run-modular-client:
	@echo "Running modular client..."
	./bin/sultry-mod -mode client

# Run the modular server
run-modular-server:
	@echo "Running modular server..."
	./bin/sultry-mod -mode server

# Run in dual mode
run-dual:
	@echo "Running in dual mode..."
	./bin/sultry -mode dual

# Run modular in dual mode
run-modular-dual:
	@echo "Running modular in dual mode..."
	./bin/sultry-mod -mode dual
