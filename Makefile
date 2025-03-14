# Makefile for Sultry TLS proxy

.PHONY: all build clean run-client run-server run-dual test fmt vet

GO = go
GO_BUILD = $(GO) build
GO_CLEAN = $(GO) clean
GO_TEST = $(GO) test
GO_VET = $(GO) vet
GO_FMT = $(GO) fmt

# Main build targets
all: build

build:
	@echo "Building Sultry..."
	$(GO_BUILD) -o bin/sultry

# Clean up binaries
clean:
	@echo "Cleaning up..."
	$(GO_CLEAN)
	rm -f bin/sultry

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

# Run the client
run-client:
	@echo "Running client..."
	./bin/sultry -mode client

# Run the server
run-server:
	@echo "Running server..."
	./bin/sultry -mode server

# Run in dual mode
run-dual:
	@echo "Running in dual mode..."
	./bin/sultry -mode dual
