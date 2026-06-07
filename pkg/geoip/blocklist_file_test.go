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
	"os"
	"path/filepath"
	"sync"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/stretchr/testify/require"
)

func TestLoadBlocklistFiles_ParsesCommaAndNewline(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, geoip.FileCountries), []byte("IR\n KP \nRU,CU\n"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, geoip.FileRegions), []byte("UA-09,\nUA-43"), 0o600))

	countries, regions, err := geoip.LoadBlocklistFiles(dir)
	require.NoError(t, err)
	require.ElementsMatch(t, []string{"IR", "KP", "RU", "CU"}, countries)
	require.ElementsMatch(t, []string{"UA-09", "UA-43"}, regions)
}

func TestLoadBlocklistFiles_MissingFilesAreEmptyNotError(t *testing.T) {
	t.Parallel()

	dir := t.TempDir() // empty: neither file exists

	countries, regions, err := geoip.LoadBlocklistFiles(dir)
	require.NoError(t, err)
	require.Empty(t, countries)
	require.Empty(t, regions)
}

func TestFingerprint_OrderAndCaseIndependent(t *testing.T) {
	t.Parallel()

	a := geoip.Fingerprint([]string{"IR", "ru", " kp "}, []string{"UA-43"})
	b := geoip.Fingerprint([]string{"RU", "KP", "IR"}, []string{"ua-43"})
	require.Equal(t, a, b, "same set in different order/case must fingerprint identically")

	c := geoip.Fingerprint([]string{"IR", "RU"}, []string{"UA-43"})
	require.NotEqual(t, a, c, "a different set must fingerprint differently")
}

func TestBlocklist_ReplaceHotSwaps(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist([]string{"IR"}, nil, true)
	require.False(t, b.Decide("RU", "").Blocked, "RU not yet blocked")

	b.Replace([]string{"IR", "RU"}, []string{"UA-43"})
	require.True(t, b.Decide("RU", "").Blocked, "RU blocked after Replace")
	require.True(t, b.Decide("UA", "43").Blocked, "UA-43 region blocked after Replace")

	countries, regions := b.Sizes()
	require.Equal(t, 2, countries)
	require.Equal(t, 1, regions)

	b.Replace(nil, nil)
	require.False(t, b.Decide("RU", "").Blocked, "cleared blocklist allows RU")
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
				b.Replace([]string{"IR", "RU"}, []string{"UA-43"})
			} else {
				b.Replace([]string{"KP"}, nil)
			}
		}
	}()

	wg.Wait()
}
