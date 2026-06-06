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

package authz_test

import (
	"errors"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/authz"
	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/stretchr/testify/require"
)

type fakeResolver struct {
	res geoip.GeoResult
	err error
}

func (f fakeResolver) Resolve(_ net.IP) (res geoip.GeoResult, err error) {
	res = f.res
	err = f.err

	return res, err
}

// byIP blocks one specific IP, to assert which XFF entry the handler uses.
type byIP struct{ blocked string }

func (s byIP) Resolve(ip net.IP) (res geoip.GeoResult, err error) {
	if ip.String() == s.blocked {
		res = geoip.GeoResult{CountryISO: "RU"}

		return res, err
	}

	res = geoip.GeoResult{CountryISO: "US"}

	return res, err
}

func handler(mode config.Mode, r geoip.Resolver, ready func() (ok bool)) (h http.Handler) {
	bl := geoip.NewBlocklist([]string{"RU", "IR"}, []string{"UA-43"}, true)
	h = authz.NewHandler(bl, r, ready, mode, "X-Forwarded-For", nil).Routes()

	return h
}

func do(h http.Handler, xff string) (rec *httptest.ResponseRecorder) {
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	if xff != "" {
		req.Header.Set("X-Forwarded-For", xff)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)

	return rec
}

func alwaysReady() (ok bool) {
	ok = true

	return ok
}

func TestCheck_EnforceBlocksSanctionedCountry(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeEnforce, fakeResolver{res: geoip.GeoResult{CountryISO: "RU"}}, alwaysReady), "5.255.255.5")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, "block", rec.Header().Get(authz.HeaderVerdict))
	require.Equal(t, "RU", rec.Header().Get(authz.HeaderCountry))
}

func TestCheck_EnforceBlocksOccupiedRegion(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeEnforce, fakeResolver{res: geoip.GeoResult{CountryISO: "UA", SubdivisionISO: "43"}}, alwaysReady), "1.2.3.4")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, geoip.ReasonBlockedRegion, rec.Header().Get(authz.HeaderReason))
}

func TestCheck_EnforceAllowsCleanClient(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeEnforce, fakeResolver{res: geoip.GeoResult{CountryISO: "US", SubdivisionISO: "CA"}}, alwaysReady), "8.8.8.8")
	require.Equal(t, http.StatusOK, rec.Code)
	require.Equal(t, "allow", rec.Header().Get(authz.HeaderVerdict))
}

func TestCheck_DetectNeverBlocks(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeDetect, fakeResolver{res: geoip.GeoResult{CountryISO: "IR"}}, alwaysReady), "2.144.0.1")
	require.Equal(t, http.StatusOK, rec.Code, "detect must never 403")
	require.Equal(t, "block", rec.Header().Get(authz.HeaderVerdict), "detect still records the would-block")
}

func TestCheck_MissingClientIPFailsClosed(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeEnforce, fakeResolver{res: geoip.GeoResult{CountryISO: "US"}}, alwaysReady), "")
	require.Equal(t, http.StatusForbidden, rec.Code)
	require.Equal(t, geoip.ReasonNoClientAddress, rec.Header().Get(authz.HeaderReason))
}

func TestCheck_ResolverErrorFailsClosed(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeEnforce, fakeResolver{err: errors.New("db down")}, alwaysReady), "8.8.8.8")
	require.Equal(t, http.StatusForbidden, rec.Code)
}

func TestCheck_UsesLeftmostXFFEntry(t *testing.T) {
	t.Parallel()

	rec := do(handler(config.ModeEnforce, byIP{blocked: "5.255.255.5"}, alwaysReady), "5.255.255.5, 10.0.0.1, 10.0.0.2")
	require.Equal(t, http.StatusForbidden, rec.Code, "must use the left-most XFF entry")
}

func TestHealth(t *testing.T) {
	t.Parallel()

	ready := false
	readyFn := func() (ok bool) { ok = ready; return ok }
	h := handler(config.ModeDetect, fakeResolver{}, readyFn)

	live := httptest.NewRecorder()
	h.ServeHTTP(live, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	require.Equal(t, http.StatusOK, live.Code)

	notReady := httptest.NewRecorder()
	h.ServeHTTP(notReady, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusServiceUnavailable, notReady.Code)

	ready = true
	nowReady := httptest.NewRecorder()
	h.ServeHTTP(nowReady, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	require.Equal(t, http.StatusOK, nowReady.Code)
}
