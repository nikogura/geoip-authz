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

package metrics_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/metrics"
	"github.com/stretchr/testify/require"
)

func scrape(t *testing.T, h http.Handler) (body string) {
	t.Helper()

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/metrics", nil))
	require.Equal(t, http.StatusOK, rec.Code)

	body = rec.Body.String()

	return body
}

func TestMetrics_ExposesGoldenSignals(t *testing.T) {
	t.Parallel()

	m, handler, err := metrics.New()
	require.NoError(t, err)

	ctx := context.Background()
	require.NoError(t, m.RegisterDBLoaded(func() (loaded bool) { loaded = true; return loaded }))

	m.InflightAdd(ctx, 1)
	m.ObserveCheck(ctx, "block", "blocked-country", true, 0.002)
	m.ObserveRefresh(ctx, true)
	m.InflightAdd(ctx, -1)

	body := scrape(t, handler)

	// OTel's prometheus exporter sanitises names and appends _total / _seconds.
	require.Contains(t, body, "geoip_authz_checks_total")
	require.Contains(t, body, "geoip_authz_check_duration_seconds")
	require.Contains(t, body, "geoip_authz_inflight_requests")
	require.Contains(t, body, "geoip_authz_db_refresh_total")
	require.Contains(t, body, "geoip_authz_db_loaded")
	// Labels from ObserveCheck are present.
	require.Contains(t, body, `verdict="block"`)
	require.Contains(t, body, `reason="blocked-country"`)
}

// TestMetrics_DurationBucketsAreSecondScaled guards against the millisecond-scaled
// OTel default boundaries returning. With the defaults ([5, 10, … 10000]), a
// microsecond-fast check lands in the first bucket and histogram_quantile reports a
// bogus ~4.75s p95. The explicit-bucket View must expose sub-millisecond boundaries
// and must NOT carry the tell-tale default 10000s boundary.
func TestMetrics_DurationBucketsAreSecondScaled(t *testing.T) {
	t.Parallel()

	m, handler, err := metrics.New()
	require.NoError(t, err)

	// A realistic geo-lookup latency: 54µs.
	m.ObserveCheck(context.Background(), "allow", "allowed", false, 0.000054)

	body := scrape(t, handler)

	// Fine, second-scaled boundaries are present (resolution where the data lives).
	require.Contains(t, body, `geoip_authz_check_duration_seconds_bucket{`)
	require.Contains(t, body, `le="0.0001"`)
	require.Contains(t, body, `le="0.001"`)
	// The millisecond-scaled OTel defaults must be gone.
	require.NotContains(t, body, `le="10000"`)
	require.NotContains(t, body, `le="7500"`)
}

func TestMetrics_NilSafe(t *testing.T) {
	t.Parallel()

	var m *metrics.Metrics // nil

	// None of these should panic.
	m.InflightAdd(context.Background(), 1)
	m.ObserveCheck(context.Background(), "allow", "allowed", false, 0.1)
	m.ObserveRefresh(context.Background(), false)
	require.NoError(t, m.RegisterDBLoaded(func() (loaded bool) { loaded = false; return loaded }))
}
