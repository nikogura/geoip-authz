# geoip-authz

A small, production-grade **external authorization (`ext_authz`) service** that
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

Every check sets `X-Geoip-Verdict` (`allow`/`block`), `X-Geoip-Country`,
`X-Geoip-Region`, and `X-Geoip-Reason` on the response for access-log capture.

## Configuration (environment, `GEOIP_` prefix)

| Variable                  | Default                              | Notes                                            |
|---------------------------|--------------------------------------|--------------------------------------------------|
| `GEOIP_MODE`              | `detect`                             | `detect` (log only) or `enforce` (403)           |
| `GEOIP_BLOCKED_COUNTRIES` | (empty)                              | comma-separated ISO-3166-1 alpha-2, e.g. `RU,IR` |
| `GEOIP_BLOCKED_REGIONS`   | (empty)                              | comma-separated ISO-3166-2, e.g. `UA-43,UA-14`   |
| `GEOIP_FAIL_CLOSED`       | `true`                               | deny when the client can't be located            |
| `GEOIP_LISTEN_ADDR`       | `:8080`                              | ext_authz + health server                        |
| `GEOIP_DOWNLOAD_URL`      | MaxMind GeoLite2-City tar.gz         | point at a caching mirror (see below)            |
| `GEOIP_ACCOUNT_ID`        | —                                    | MaxMind account ID (HTTP basic-auth)             |
| `GEOIP_LICENSE_KEY`       | —                                    | MaxMind license key (HTTP basic-auth)            |
| `GEOIP_REFRESH_EVERY`     | `24h`                                | jittered; retains last-good on failure           |
| `GEOIP_CLIENT_IP_HEADER`  | `X-Forwarded-For`                    | left-most entry is used                          |
| `GEOIP_DB_PATH`           | —                                    | load a local `.mmdb` instead of downloading      |

## Running

```
GEOIP_MODE=enforce \
GEOIP_BLOCKED_COUNTRIES=RU,IR,KP \
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

## Development

```
make test    # go test -race -cover
make lint    # namedreturns + golangci-lint (both required)
make build
```

## License

MIT — see [LICENSE](LICENSE).
