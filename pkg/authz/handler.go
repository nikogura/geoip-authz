// Copyright © 2026 Nik Ogura <nik.ogura@gmail.com>
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package authz

import (
	"log/slog"
	"net"
	"net/http"
	"strings"

	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/nikogura/geoip-authz/pkg/geoip"
)

// Response headers set on every ext_authz check so the verdict is observable in
// the proxy's access logs (and so backends could consume the geo data later).
const (
	// HeaderVerdict is "block" or "allow".
	HeaderVerdict = "X-Geoip-Verdict"
	// HeaderCountry is the resolved ISO-3166-1 alpha-2 country code.
	HeaderCountry = "X-Geoip-Country"
	// HeaderRegion is the resolved ISO-3166-2 region code.
	HeaderRegion = "X-Geoip-Region"
	// HeaderReason is the machine-readable verdict reason.
	HeaderReason = "X-Geoip-Reason"
)

// Handler answers ext_authz checks and health probes against a geoip.Blocklist
// and Resolver.
type Handler struct {
	blocklist      *geoip.Blocklist
	resolver       geoip.Resolver
	ready          func() (ready bool)
	mode           config.Mode
	clientIPHeader string
	log            *slog.Logger
}

// NewHandler builds a Handler. ready reports whether the geo database is loaded
// (used by the readiness probe).
func NewHandler(blocklist *geoip.Blocklist, resolver geoip.Resolver, ready func() (ready bool), mode config.Mode, clientIPHeader string, log *slog.Logger) (h *Handler) {
	if log == nil {
		log = slog.Default()
	}

	h = &Handler{
		blocklist:      blocklist,
		resolver:       resolver,
		ready:          ready,
		mode:           mode,
		clientIPHeader: clientIPHeader,
		log:            log,
	}

	return h
}

// Routes returns the HTTP mux: "/healthz", "/readyz", and a catch-all ext_authz
// check. Kubernetes probes hit the health paths directly; the proxy forwards
// real client requests to the catch-all.
func (h *Handler) Routes() (mux *http.ServeMux) {
	mux = http.NewServeMux()
	mux.HandleFunc("/healthz", h.handleHealthz)
	mux.HandleFunc("/readyz", h.handleReadyz)
	mux.HandleFunc("/", h.handleCheck)

	return mux
}

// handleHealthz always succeeds once the process is serving.
func (h *Handler) handleHealthz(w http.ResponseWriter, _ *http.Request) {
	w.WriteHeader(http.StatusOK)
}

// handleReadyz reports 200 only once a database is loaded, so traffic is not
// routed to a replica that would fail every lookup closed.
func (h *Handler) handleReadyz(w http.ResponseWriter, _ *http.Request) {
	if h.ready != nil && !h.ready() {
		w.WriteHeader(http.StatusServiceUnavailable)

		return
	}

	w.WriteHeader(http.StatusOK)
}

// handleCheck is the ext_authz decision. It resolves the client IP from the
// configured header, evaluates the blocklist, annotates the response, and
// returns 403 (enforce + blocked) or 200 otherwise. In detect mode it always
// returns 200 but still annotates and logs the would-block verdict.
func (h *Handler) handleCheck(w http.ResponseWriter, r *http.Request) {
	clientIP := clientIPFromHeader(r.Header.Get(h.clientIPHeader))
	verdict := h.blocklist.Evaluate(h.resolver, clientIP)

	w.Header().Set(HeaderCountry, verdict.CountryISO)
	w.Header().Set(HeaderRegion, verdict.RegionISO)
	w.Header().Set(HeaderReason, verdict.Reason)

	deny := verdict.Blocked && h.mode == config.ModeEnforce

	if verdict.Blocked {
		w.Header().Set(HeaderVerdict, "block")
	} else {
		w.Header().Set(HeaderVerdict, "allow")
	}

	h.log.InfoContext(r.Context(), "geoip check",
		"client_ip", clientIP.String(),
		"country", verdict.CountryISO,
		"region", verdict.RegionISO,
		"reason", verdict.Reason,
		"blocked", verdict.Blocked,
		"mode", string(h.mode),
		"denied", deny,
	)

	if deny {
		http.Error(w, "forbidden: geographic restriction", http.StatusForbidden)

		return
	}

	w.WriteHeader(http.StatusOK)
}

// clientIPFromHeader extracts the client IP from an X-Forwarded-For-style header
// value, taking the left-most entry (the original client as seen by the proxy
// after PROXY-protocol recovery). Returns nil when absent/unparseable, which
// Evaluate treats as fail-closed.
func clientIPFromHeader(header string) (ip net.IP) {
	if header == "" {
		return ip
	}

	first := header
	if idx := strings.IndexByte(header, ','); idx >= 0 {
		first = header[:idx]
	}

	first = strings.TrimSpace(first)

	host, _, splitErr := net.SplitHostPort(first)
	if splitErr == nil {
		first = host
	}

	ip = net.ParseIP(first)

	return ip
}
