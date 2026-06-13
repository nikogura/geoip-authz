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

func writeRuntimeConfig(t *testing.T, body string) (path string) {
	t.Helper()

	path = filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, []byte(body), 0o600))

	return path
}

// newReloadTestService builds a Service seeded with a deliberately-stale runtime
// (detect, fail-open, empty blocklist) so the first reloadRuntime against the
// file is observably a change.
func newReloadTestService(t *testing.T, path string) (svc *Service) {
	t.Helper()

	svc = &Service{
		cfg:       config.Config{ConfigFile: path},
		blocklist: geoip.NewBlocklist(nil, nil, false),
		log:       slog.Default(),
	}

	seed := config.ModeDetect
	svc.mode.Store(&seed)

	return svc
}

// TestReloadRuntime_HotSwapsModeFailClosedAndBlocklist is the core guarantee:
// one edit to the single config file atomically swaps mode, fail-closed, AND the
// blocklist — with no restart — and an unchanged read is a no-op.
func TestReloadRuntime_HotSwapsModeFailClosedAndBlocklist(t *testing.T) {
	t.Parallel()

	path := writeRuntimeConfig(t, "mode: enforce\nfailClosed: true\nblocklist:\n  countries: |\n    IR\n    KP\n  regions: |\n    UA-43\n")
	svc := newReloadTestService(t, path)

	require.Equal(t, config.ModeDetect, svc.currentMode(), "seeded stale: detect")
	require.False(t, svc.blocklist.Decide("", "").Blocked, "seeded stale: fail-open")
	require.False(t, svc.blocklist.Decide("IR", "").Blocked, "seeded stale: empty blocklist")

	changed, err := svc.reloadRuntime()
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, config.ModeEnforce, svc.currentMode(), "mode hot-swapped")
	require.True(t, svc.blocklist.Decide("IR", "").Blocked, "IR blocked after reload")
	require.True(t, svc.blocklist.Decide("UA", "43").Blocked, "UA-43 blocked after reload")
	require.True(t, svc.blocklist.Decide("", "").Blocked, "fail-closed hot-swapped on")

	// Identical re-read must be a no-op (no churn / no spurious events).
	changed, err = svc.reloadRuntime()
	require.NoError(t, err)
	require.False(t, changed)
}

// TestReloadRuntime_PicksUpEdits confirms a later edit to the file is applied on
// the next reload without a restart.
func TestReloadRuntime_PicksUpEdits(t *testing.T) {
	t.Parallel()

	path := writeRuntimeConfig(t, "mode: enforce\nfailClosed: true\nblocklist:\n  countries: |\n    IR\n    KP\n")
	svc := newReloadTestService(t, path)

	_, err := svc.reloadRuntime()
	require.NoError(t, err)
	require.True(t, svc.blocklist.Decide("KP", "").Blocked)

	// Edit: drop KP, flip to detect, fail-open.
	require.NoError(t, os.WriteFile(path, []byte("mode: detect\nfailClosed: false\nblocklist:\n  countries: |\n    IR\n"), 0o600))

	changed, err := svc.reloadRuntime()
	require.NoError(t, err)
	require.True(t, changed)
	require.Equal(t, config.ModeDetect, svc.currentMode())
	require.False(t, svc.blocklist.Decide("KP", "").Blocked, "KP removed without a restart")
	require.False(t, svc.blocklist.Decide("", "").Blocked, "fail-open after edit")
}

// TestReloadRuntime_InvalidModeRetainsLastGood is the validate-on-swap
// guarantee: a fat-fingered mode (e.g. "block") is rejected and the last-good
// runtime stands, rather than taking the gate down.
func TestReloadRuntime_InvalidModeRetainsLastGood(t *testing.T) {
	t.Parallel()

	path := writeRuntimeConfig(t, "mode: enforce\nfailClosed: true\nblocklist:\n  countries: |\n    IR\n")
	svc := newReloadTestService(t, path)

	_, err := svc.reloadRuntime()
	require.NoError(t, err)
	require.Equal(t, config.ModeEnforce, svc.currentMode())

	// Garbage mode + a would-be new entry that must NOT be applied.
	require.NoError(t, os.WriteFile(path, []byte("mode: block\nblocklist:\n  countries: |\n    IR\n    RU\n"), 0o600))

	changed, err := svc.reloadRuntime()
	require.ErrorIs(t, err, config.ErrInvalidMode, "invalid mode must error")
	require.False(t, changed, "no swap on invalid config")
	require.Equal(t, config.ModeEnforce, svc.currentMode(), "last-good mode retained")
	require.False(t, svc.blocklist.Decide("RU", "").Blocked, "last-good blocklist retained (RU not added)")
}
