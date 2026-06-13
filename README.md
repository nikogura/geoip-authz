# geoip-authz

A small **external authorization (`ext_authz`) service** that
allows or denies HTTP requests by the client's **GeoIP location**. Point Envoy
(or any reverse proxy that speaks the HTTP ext_authz contract) at it to enforce
country/region access policy at the edge.

It exists because Envoy's native MaxMind geoip filter ships only in the
`-contrib` images and is documented as *"work-in-progress… not intended for
production use."* `geoip-authz` keeps the geo decision in a small, testable,
fail-closed service instead.

## What it does

- Loads a **MaxMind GeoLite2-City** database into memory and refreshes it
  periodically (last-good retained on failure).
- On each request, resolves the client IP — read from a configurable request
  header (`GEOIP_CLIENT_IP_HEADER`, default `X-Forwarded-For`; left-most entry) —
  to an ISO-3166-1 country and ISO-3166-2 subdivision.
- Denies (HTTP **403**) when the country or `<country>-<subdivision>` region is on
  an **operator-supplied blocklist**; otherwise allows (**200**).
- **Fail-closed**: an un-locatable client (missing/unparseable IP, lookup error,
  or database not yet loaded) is denied. Configurable.
- **Detect mode**: always returns 200 but annotates and logs the would-block
  verdict — run it in the request path to validate policy before enforcing.

The service ships **no built-in blocklist**: it is policy-neutral and reusable.
You supply the country/region list via configuration.

## HTTP surface

| Path      | Purpose                                                    |
|-----------|------------------------------------------------------------|
| `/`       | ext_authz check (catch-all). `2xx` = allow, `403` = deny   |
| `/healthz`| liveness                                                   |
| `/readyz` | readiness — `200` only once the database is loaded         |
| `/metrics`| Prometheus metrics (golden signals — see Observability)    |

Every check sets `X-Geoip-Verdict` (`allow`/`block`), `X-Geoip-Country`,
`X-Geoip-Region`, and `X-Geoip-Reason` on the response for access-log capture.

## Observability

- **Metrics** — OpenTelemetry instruments exported in Prometheus format at
  `/metrics`. The golden signals plus DB health:
  - `geoip_authz_checks_total{verdict,reason,denied}` — traffic + errors
  - `geoip_authz_check_duration_seconds` — latency histogram
  - `geoip_authz_inflight_requests` — saturation
  - `geoip_authz_db_refresh_total{success}` and `geoip_authz_db_loaded` — DB health
- **Tracing** — OpenTelemetry spans (`geoip.authz.check`). Disabled (no-op) unless
  an OTLP endpoint is set via the standard `OTEL_EXPORTER_OTLP_ENDPOINT` (or
  `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT`); then spans export over OTLP/HTTP.
- **Logs** — structured JSON (`slog`), one line per check, including the
  `trace_id` for correlation when tracing is enabled.

## Configuration (single YAML file, file-authoritative)

All configuration lives in **one YAML file** (default `/etc/geoip-authz/config.yaml`;
override the path with `GEOIP_CONFIG_FILE`). Mount a ConfigMap there. The file is
the single source of truth — there are no per-setting environment variables.

```yaml
# /etc/geoip-authz/config.yaml
mode: enforce                       # detect (log only) or enforce (403)   [hot-reload]
failClosed: true                    # deny when the client can't be located [hot-reload]
blocklist:                          #                                       [hot-reload]
  countries: |                      # ISO-3166-1 alpha-2 — | block, one per line
    IR
    KP
    RU
  regions: |                        # ISO-3166-2 — needs the City database
    UA-09
    UA-14
    UA-43
listenAddr: ":8080"                 # ext_authz + health server             [boot]
clientIPHeader: "X-Forwarded-For"   # left-most entry is used               [boot]
geoDownloadURL: "https://..."       # MaxMind GeoLite2-City tar.gz / mirror [boot]
refreshEvery: 24h                   # DB re-pull; jittered, last-good kept   [boot]
reloadEvery: 30s                    # how often this file is re-read         [boot]
# dbPath: /data/city.mmdb           # load a local .mmdb instead of downloading [boot]
```

`countries`/`regions` accept a **`|` block scalar (one entry per line), a
comma-separated string, or a YAML sequence** — all equivalent; entries are
trimmed and empties dropped. `failClosed` defaults to **true** when omitted (safe
default for a sanctions gate). `mode` defaults to `detect`; any value other than
`detect`/`enforce` is rejected.

### Secrets are the one exception (environment, not the file)

MaxMind credentials are **never** put in the config file — they come from the
environment so they can be injected from a Secret:

| Variable            | Notes                                                      |
|---------------------|------------------------------------------------------------|
| `GEOIP_CONFIG_FILE` | config file path (default `/etc/geoip-authz/config.yaml`)  |
| `GEOIP_ACCOUNT_ID`  | MaxMind account ID (HTTP basic-auth) — optional            |
| `GEOIP_LICENSE_KEY` | MaxMind license key (HTTP basic-auth) — optional           |

Credentials are **optional** — omit them when using `dbPath`, an unauthenticated
mirror, or a proxy that injects its own auth.

### Hot-reloading (no restart)

The kubelet updates a mounted ConfigMap in place; the service re-reads the file
every `reloadEvery` (default 30s) and **atomically swaps** the hot-reloadable
subset — **`mode`, `failClosed`, and the blocklist** — when the content changes.
In-flight checks finish against the old policy; subsequent ones see the new one.
An unchanged read is a no-op. A read **or validation** error (e.g. a fat-fingered
`mode: block`) is logged and the **last-good policy is retained** — a typo never
takes the gate down. Boot-only fields (listen address, download URL, intervals)
change only on a pod restart. Reloads and the live blocklist size are exposed as
metrics (`geoip_authz_blocklist_reload_total`, `geoip_authz_blocklist_size`) and
logged as a `config hot-reloaded` event.

## Running

```
GEOIP_CONFIG_FILE=./config.yaml \
GEOIP_ACCOUNT_ID=xxxx GEOIP_LICENSE_KEY=yyyy \
geoip-authz server
```

## Feeding the database — caching mirror

MaxMind rate-limits downloads, so in a fleet you don't want every replica pulling
from MaxMind directly. Run a caching mirror once and point `GEOIP_DOWNLOAD_URL`
at it. [`geoip-cache-proxy`](https://github.com/gabe565/geoip-cache-proxy) is a
good fit — a transparent Redis-backed cache in front of MaxMind's
download/update endpoints (I contributed to it upstream; my fork lives at
[`nikogura/geoip-cache-proxy`](https://github.com/nikogura/geoip-cache-proxy)).
`geoip-authz` authenticates to the mirror with the same MaxMind account ID /
license key.

## Wiring into Envoy Gateway

Attach a `SecurityPolicy` with HTTP ext_authz to a Gateway/HTTPRoute. The client
IP must be forwarded, so set `headersToExtAuth: [x-forwarded-for]` (an HTTP
ext_authz backend otherwise only receives Host/Method/Path/Content-Length/
Authorization):

```yaml
apiVersion: gateway.envoyproxy.io/v1alpha1
kind: SecurityPolicy
metadata:
  name: geoip
spec:
  targetRefs:
    - { group: gateway.networking.k8s.io, kind: HTTPRoute, name: my-app }
  extAuth:
    failOpen: false
    headersToExtAuth: ["x-forwarded-for"]
    http:
      backendRefs:
        - { name: geoip-authz, namespace: geoip-authz, port: 8080 }
```

## Deploying to Kubernetes

Two equivalent options ship in this repo:

- **Kustomize** — `kubernetes/` is a runnable example (namespace, ConfigMap with a
  `|`-block blocklist, Secret stub, Deployment, Service, ServiceMonitor):
  `kubectl apply -k kubernetes/`.
- **Helm** — `charts/geoip-authz/`: `helm install geoip-authz ./charts/geoip-authz`.
  The chart is also published as an OCI artifact:
  `helm install geoip-authz oci://ghcr.io/nikogura/charts/geoip-authz`.

Images are published multi-arch (amd64/arm64) to `ghcr.io/nikogura/geoip-authz`.

## Development

```
make test    # go test -race -cover
make lint    # namedreturns + golangci-lint (both required)
make build
```

## License

MIT — see [LICENSE](LICENSE).
