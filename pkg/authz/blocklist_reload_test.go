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

// White-box tests for unexported runtime helpers.
package authz

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/stretchr/testify/require"
)

func writeBlocklist(t *testing.T, dir, countries, regions string) {
	t.Helper()
	require.NoError(t, os.WriteFile(filepath.Join(dir, geoip.FileCountries), []byte(countries), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, geoip.FileRegions), []byte(regions), 0o600))
}

// TestReloadBlocklist_PicksUpFileChanges is the core hot-reload guarantee: an
// edit to the mounted files is applied on the next reload, with no restart, and
// an unchanged read is a no-op.
func TestReloadBlocklist_PicksUpFileChanges(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	writeBlocklist(t, dir, "IR\nKP", "UA-43")

	svc := &Service{
		cfg:       config.Config{BlocklistDir: dir, FailClosed: true},
		blocklist: geoip.NewBlocklist(nil, nil, true),
		log:       slog.Default(),
	}

	// Initial load: empty -> file contents = changed.
	changed, err := svc.reloadBlocklist()
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, svc.blocklist.Decide("IR", "").Blocked)
	require.True(t, svc.blocklist.Decide("UA", "43").Blocked)
	require.False(t, svc.blocklist.Decide("RU", "").Blocked)

	countries, regions := svc.blocklist.Sizes()
	require.Equal(t, 2, countries)
	require.Equal(t, 1, regions)

	// Re-reading identical files must NOT report a change (no churn).
	changed, err = svc.reloadBlocklist()
	require.NoError(t, err)
	require.False(t, changed)

	// Edit the files: a newly-sanctioned country is picked up on next reload.
	writeBlocklist(t, dir, "IR\nKP\nRU", "UA-43")
	changed, err = svc.reloadBlocklist()
	require.NoError(t, err)
	require.True(t, changed)
	require.True(t, svc.blocklist.Decide("RU", "").Blocked, "newly-added RU is now blocked without a restart")
}

// TestReloadBlocklist_MissingDirIsEmptyPolicy confirms a missing directory loads
// an empty policy rather than erroring (self-healing).
func TestReloadBlocklist_MissingDirIsEmptyPolicy(t *testing.T) {
	t.Parallel()

	svc := &Service{
		cfg:       config.Config{BlocklistDir: filepath.Join(t.TempDir(), "absent"), FailClosed: true},
		blocklist: geoip.NewBlocklist([]string{"IR"}, nil, true),
		log:       slog.Default(),
	}

	changed, err := svc.reloadBlocklist()
	require.NoError(t, err)
	require.True(t, changed, "swapping the seeded IR policy for the empty file policy is a change")

	countries, regions := svc.blocklist.Sizes()
	require.Equal(t, 0, countries)
	require.Equal(t, 0, regions)
}
