.PHONY: lint test test-all build clean

# Lint runs the mandatory custom namedreturns linter, then golangci-lint.
# Sequential + fail-fast: if namedreturns fails, golangci-lint does not run.
lint:
	@echo "Running namedreturns linter..."
	namedreturns ./...
	@echo "Running golangci-lint..."
	golangci-lint run

# Test runs all unit tests with the race detector.
test:
	go test -race -cover -count=1 ./...

# Test-all runs unit tests and lint.
test-all: test lint

# Build compiles the binary into the current directory.
build:
	go build -o geoip-authz .

# Clean removes build artifacts.
clean:
	rm -f geoip-authz
