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

package config_test

import (
	"testing"
	"time"

	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestLoad_Defaults(t *testing.T) {
	// Not parallel: mutates process environment.
	t.Setenv("GEOIP_MODE", "")
	t.Setenv("GEOIP_REFRESH_EVERY", "")

	cfg, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, config.ModeDetect, cfg.Mode)
	require.Equal(t, ":8080", cfg.ListenAddr)
	require.Equal(t, 24*time.Hour, cfg.RefreshEvery)
	require.True(t, cfg.FailClosed, "fail-closed must default true")
	require.Empty(t, cfg.BlockedCountries)
}

func TestLoad_OverridesFromEnv(t *testing.T) {
	t.Setenv("GEOIP_MODE", "enforce")
	t.Setenv("GEOIP_REFRESH_EVERY", "1h")
	t.Setenv("GEOIP_ACCOUNT_ID", "424242")
	t.Setenv("GEOIP_LICENSE_KEY", "secret")
	t.Setenv("GEOIP_BLOCKED_COUNTRIES", "IR, KP ,RU")
	t.Setenv("GEOIP_BLOCKED_REGIONS", "UA-43")
	t.Setenv("GEOIP_FAIL_CLOSED", "false")

	cfg, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, config.ModeEnforce, cfg.Mode)
	require.Equal(t, time.Hour, cfg.RefreshEvery)
	require.Equal(t, "424242", cfg.AccountID)
	require.Equal(t, "secret", cfg.LicenseKey)
	require.Equal(t, []string{"IR", "KP", "RU"}, cfg.BlockedCountries, "comma list must trim and split")
	require.Equal(t, []string{"UA-43"}, cfg.BlockedRegions)
	require.False(t, cfg.FailClosed)
}

func TestLoad_InvalidModeRejected(t *testing.T) {
	t.Setenv("GEOIP_MODE", "audit")

	_, err := config.Load()
	require.ErrorIs(t, err, config.ErrInvalidMode)
}

func TestParseAccountID(t *testing.T) {
	t.Parallel()

	id, err := config.ParseAccountID("12345")
	require.NoError(t, err)
	require.Equal(t, 12345, id)

	id, err = config.ParseAccountID("")
	require.NoError(t, err)
	require.Equal(t, 0, id)

	_, err = config.ParseAccountID("abc")
	require.Error(t, err)
}
