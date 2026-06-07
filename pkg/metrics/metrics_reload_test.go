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
	"testing"

	"github.com/nikogura/geoip-authz/pkg/metrics"
	"github.com/stretchr/testify/require"
)

func TestMetrics_BlocklistReloadAndSize(t *testing.T) {
	t.Parallel()

	m, handler, err := metrics.New()
	require.NoError(t, err)

	require.NoError(t, m.RegisterBlocklistSize(func() (countries, regions int) { countries, regions = 23, 3; return countries, regions }))
	m.ObserveReload(context.Background(), true)

	body := scrape(t, handler)

	require.Contains(t, body, "geoip_authz_blocklist_reload_total")
	require.Contains(t, body, `success="true"`)
	require.Contains(t, body, "geoip_authz_blocklist_size")
	require.Contains(t, body, `scope="country"`)
	require.Contains(t, body, `scope="region"`)
}

func TestMetrics_ReloadAndSizeNilSafe(t *testing.T) {
	t.Parallel()

	var m *metrics.Metrics // nil

	m.ObserveReload(context.Background(), false)
	require.NoError(t, m.RegisterBlocklistSize(func() (countries, regions int) { countries, regions = 0, 0; return countries, regions }))
}
