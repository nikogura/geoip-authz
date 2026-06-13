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

package geoip_test

import (
	"sync"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/stretchr/testify/require"
)

// sanctionCountries is a representative blocklist used as a test fixture. The
// service ships no built-in list; the operator supplies one via config.
//
//nolint:gochecknoglobals // test fixture
var sanctionCountries = []string{
	"IR", "KP", "SY", "SD", "RU", "AF", "BY", "MM", "CU", "AL", "BA", "CF",
	"CD", "ET", "IQ", "LB", "LY", "ML", "NI", "SO", "SS", "VE", "YE",
}

//nolint:gochecknoglobals // test fixture
var sanctionRegions = []string{"UA-09", "UA-14", "UA-43"}

func TestDecide_BlockedCountries(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist(sanctionCountries, sanctionRegions, true)

	for _, country := range sanctionCountries {
		t.Run(country, func(t *testing.T) {
			t.Parallel()

			v := b.Decide(country, "")
			require.True(t, v.Blocked, "country %s must be blocked", country)
			require.Equal(t, geoip.ReasonBlockedCountry, v.Reason)
		})
	}
}

func TestDecide_BlockedRegions(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist(sanctionCountries, sanctionRegions, true)

	tests := []struct {
		name string
		sub  string
	}{
		{"Luhansk", "09"},
		{"Donetsk", "14"},
		{"Crimea", "43"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := b.Decide("UA", tt.sub)
			require.True(t, v.Blocked, "UA-%s (%s) must be blocked", tt.sub, tt.name)
			require.Equal(t, geoip.ReasonBlockedRegion, v.Reason)
		})
	}
}

func TestDecide_Allowed(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist(sanctionCountries, sanctionRegions, true)

	tests := []struct {
		name    string
		country string
		sub     string
	}{
		{"UnitedStates", "US", "CA"},
		{"Germany_Bavaria_not_country_BY", "DE", "BY"},
		{"Ukraine_non_occupied", "UA", "30"},
		{"Japan", "JP", ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			v := b.Decide(tt.country, tt.sub)
			require.False(t, v.Blocked, "%s must be allowed", tt.name)
			require.Equal(t, geoip.ReasonAllowed, v.Reason)
		})
	}
}

func TestDecide_EmptyBlocklistAllowsKnownCountry(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist(nil, nil, true)

	v := b.Decide("RU", "")
	require.False(t, v.Blocked, "empty blocklist must not block a known country")
	require.Equal(t, geoip.ReasonAllowed, v.Reason)
}

func TestDecide_FailClosedOnEmptyCountry(t *testing.T) {
	t.Parallel()

	closed := geoip.NewBlocklist(sanctionCountries, nil, true)
	require.True(t, closed.Decide("", "").Blocked, "fail-closed must block an un-locatable client")
	require.Equal(t, geoip.ReasonLookupFailed, closed.Decide("", "").Reason)

	open := geoip.NewBlocklist(sanctionCountries, nil, false)
	require.False(t, open.Decide("", "").Blocked, "fail-open must allow an un-locatable client")
}

func TestDecide_CaseAndWhitespaceInsensitive(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist([]string{" ru "}, []string{" ua-43 "}, true)
	require.True(t, b.Decide(" ru ", "").Blocked, "lowercase/padded country must match")
	require.True(t, b.Decide("ua", "43").Blocked, "lowercase region must match")
}

func TestReplace_HotSwapsPolicyAndFailClosed(t *testing.T) {
	t.Parallel()

	// Start fail-open with only IR blocked.
	b := geoip.NewBlocklist([]string{"IR"}, nil, false)
	require.False(t, b.Decide("RU", "").Blocked, "RU not yet blocked")
	require.False(t, b.Decide("", "").Blocked, "fail-open allows an un-locatable client")

	// Replace swaps the lists AND the fail-closed behaviour atomically.
	b.Replace([]string{"IR", "RU"}, []string{"UA-43"}, true)
	require.True(t, b.Decide("RU", "").Blocked, "RU blocked after Replace")
	require.True(t, b.Decide("UA", "43").Blocked, "UA-43 region blocked after Replace")
	require.True(t, b.Decide("", "").Blocked, "fail-closed now blocks an un-locatable client")

	countries, regions := b.Sizes()
	require.Equal(t, 2, countries)
	require.Equal(t, 1, regions)

	// Clear everything and go fail-open again.
	b.Replace(nil, nil, false)
	require.False(t, b.Decide("RU", "").Blocked, "cleared blocklist allows RU")
	require.False(t, b.Decide("", "").Blocked, "fail-open again allows an un-locatable client")
}

// TestBlocklist_ConcurrentReplaceAndDecide exercises the atomic swap under the
// race detector: readers must never observe a torn/half-updated policy.
func TestBlocklist_ConcurrentReplaceAndDecide(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist([]string{"IR"}, nil, true)

	var wg sync.WaitGroup

	for range 8 {
		wg.Add(1)

		go func() {
			defer wg.Done()

			for range 1000 {
				_ = b.Decide("IR", "")
				_, _ = b.Sizes()
			}
		}()
	}

	wg.Add(1)

	go func() {
		defer wg.Done()

		for i := range 1000 {
			if i%2 == 0 {
				b.Replace([]string{"IR", "RU"}, []string{"UA-43"}, true)
			} else {
				b.Replace([]string{"KP"}, nil, false)
			}
		}
	}()

	wg.Wait()
}
