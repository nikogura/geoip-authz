# Build stage — pinned to the host arch for native compilation. Go
# cross-compiles via GOOS/GOARCH, so no QEMU is needed in the build.
FROM --platform=$BUILDPLATFORM golang:1.24 AS builder

# TARGETOS / TARGETARCH are supplied automatically by `docker buildx build`
# when invoked with --platform. Declared WITHOUT defaults so a bare
# `docker build` (no buildx, no --platform) fails loudly instead of silently
# producing a wrong-arch binary inside a per-arch manifest tag.
ARG TARGETOS
ARG TARGETARCH

WORKDIR /src

COPY go.mod go.sum ./
RUN go mod download

COPY . .

RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -ldflags="-s -w" -trimpath -o /geoip-authz .

# Runtime: distroless static (multi-arch) for a zero-CGO binary.
FROM gcr.io/distroless/static-debian12:nonroot

COPY --from=builder --chown=nonroot:nonroot /geoip-authz /geoip-authz

ENTRYPOINT ["/geoip-authz", "server"]
