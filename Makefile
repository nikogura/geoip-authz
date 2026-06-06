.PHONY: lint test test-go test-distro test-all build clean

# Lint runs the mandatory custom namedreturns linter, then golangci-lint.
# Sequential + fail-fast: if namedreturns fails, golangci-lint does not run.
lint:
	@echo "Running namedreturns linter..."
	namedreturns ./...
	@echo "Running golangci-lint..."
	golangci-lint run

# Test runs ALL tests — Go code AND the Kubernetes distribution (kustomize + helm).
test: test-go test-distro

# test-go runs the unit tests with the race detector.
test-go:
	@echo "Running Go tests..."
	go test -race -cover -count=1 ./...

# test-distro renders the kustomize example and the Helm chart so a broken distro
# fails the build like any other test. Requires kustomize and helm on PATH.
test-distro:
	@echo "Validating kustomize example..."
	kustomize build kubernetes >/dev/null
	@echo "Linting Helm chart..."
	helm lint charts/geoip-authz
	@echo "Templating Helm chart..."
	helm template t charts/geoip-authz \
		--set blockedCountries='{RU,IR}' \
		--set blockedRegions='{UA-43}' \
		--set serviceMonitor.enabled=true \
		--set maxmind.accountId=1 --set maxmind.licenseKey=x >/dev/null

# Test-all runs every test plus lint.
test-all: test lint

# Build compiles the binary into the current directory.
build:
	go build -o geoip-authz .

# Clean removes build artifacts.
clean:
	rm -f geoip-authz
