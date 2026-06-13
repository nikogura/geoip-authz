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
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/stretchr/testify/require"
)

// writeConfig writes body to a temp config.yaml and returns its path.
func writeConfig(t *testing.T, body string) (path string) {
	t.Helper()

	path = filepath.Join(t.TempDir(), "config.yaml")

	err := os.WriteFile(path, []byte(body), 0o600)
	require.NoError(t, err)

	return path
}

// fullConfig exercises every field, with the blocklist in `|` block-scalar form
// (one entry per line) — the ergonomics carried over from the old blocklist
// files.
const fullConfig = `
mode: enforce
failClosed: false
listenAddr: ":9090"
geoDownloadURL: "https://mirror.example/db.tar.gz"
refreshEvery: 1h
httpTimeout: 5s
clientIPHeader: "X-Real-IP"
dbPath: "/data/city.mmdb"
reloadEvery: 15s
blocklist:
  countries: |
    IR
    KP
    RU
  regions: |
    UA-09
    UA-14
`

func TestLoadFile_FullConfig(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, fullConfig)

	cfg, err := config.LoadFile(path)
	require.NoError(t, err)

	require.Equal(t, config.ModeEnforce, cfg.Mode)
	require.False(t, cfg.FailClosed)
	require.Equal(t, ":9090", cfg.ListenAddr)
	require.Equal(t, "https://mirror.example/db.tar.gz", cfg.DownloadURL)
	require.Equal(t, time.Hour, cfg.RefreshEvery)
	require.Equal(t, 5*time.Second, cfg.HTTPTimeout)
	require.Equal(t, "X-Real-IP", cfg.ClientIPHeader)
	require.Equal(t, "/data/city.mmdb", cfg.DBPath)
	require.Equal(t, 15*time.Second, cfg.ReloadEvery)
	require.Equal(t, []string{"IR", "KP", "RU"}, cfg.BlockedCountries)
	require.Equal(t, []string{"UA-09", "UA-14"}, cfg.BlockedRegions)
	require.Equal(t, path, cfg.ConfigFile)
}

func TestLoadFile_Defaults(t *testing.T) {
	t.Parallel()

	// Minimal file: only mode set; everything else must default.
	path := writeConfig(t, "mode: detect\n")

	cfg, err := config.LoadFile(path)
	require.NoError(t, err)

	require.Equal(t, config.ModeDetect, cfg.Mode)
	require.Equal(t, ":8080", cfg.ListenAddr)
	require.Equal(t, 24*time.Hour, cfg.RefreshEvery)
	require.Equal(t, 60*time.Second, cfg.HTTPTimeout)
	require.Equal(t, "X-Forwarded-For", cfg.ClientIPHeader)
	require.Equal(t, 30*time.Second, cfg.ReloadEvery)
	require.True(t, cfg.FailClosed, "fail-closed must default true when omitted")
	require.Empty(t, cfg.BlockedCountries)
	require.Empty(t, cfg.BlockedRegions)
}

func TestLoadFile_ModeDefaultsToDetectAndLowercases(t *testing.T) {
	t.Parallel()

	empty := writeConfig(t, "{}\n")
	cfg, err := config.LoadFile(empty)
	require.NoError(t, err)
	require.Equal(t, config.ModeDetect, cfg.Mode, "empty file → detect")

	upper := writeConfig(t, "mode: ENFORCE\n")
	cfg, err = config.LoadFile(upper)
	require.NoError(t, err)
	require.Equal(t, config.ModeEnforce, cfg.Mode, "mode must lowercase")
}

func TestLoadFile_InvalidModeRejected(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "mode: block\n")

	_, err := config.LoadFile(path)
	require.ErrorIs(t, err, config.ErrInvalidMode, "'block' is not a valid mode")
}

func TestLoadFile_FailClosedRespectsExplicitFalse(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "mode: detect\nfailClosed: false\n")

	cfg, err := config.LoadFile(path)
	require.NoError(t, err)
	require.False(t, cfg.FailClosed)
}

func TestLoadFile_ListFormsAllParse(t *testing.T) {
	t.Parallel()

	cases := map[string]string{
		"block scalar":      "blocklist:\n  countries: |\n    IR\n    KP\n    RU\n",
		"comma inline":      "blocklist:\n  countries: \"IR, KP ,RU\"\n",
		"yaml sequence":     "blocklist:\n  countries: [IR, KP, RU]\n",
		"comma+newline mix": "blocklist:\n  countries: |\n    IR, KP\n    RU\n",
	}

	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			path := writeConfig(t, "mode: detect\n"+body)

			cfg, err := config.LoadFile(path)
			require.NoError(t, err)
			require.Equal(t, []string{"IR", "KP", "RU"}, cfg.BlockedCountries)
		})
	}
}

func TestLoadFile_InvalidDurationRejected(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "mode: detect\nrefreshEvery: \"not-a-duration\"\n")

	_, err := config.LoadFile(path)
	require.Error(t, err)
}

func TestLoadFile_SecretsComeFromEnvNotFile(t *testing.T) {
	// Not parallel: mutates process environment.
	t.Setenv("GEOIP_ACCOUNT_ID", "424242")
	t.Setenv("GEOIP_LICENSE_KEY", "s3cret")

	path := writeConfig(t, "mode: enforce\n")

	cfg, err := config.LoadFile(path)
	require.NoError(t, err)
	require.Equal(t, "424242", cfg.AccountID)
	require.Equal(t, "s3cret", cfg.LicenseKey)
}

func TestLoadFile_MissingFileErrors(t *testing.T) {
	t.Parallel()

	_, err := config.LoadFile(filepath.Join(t.TempDir(), "does-not-exist.yaml"))
	require.Error(t, err)
}

func TestLoadRuntime_ReturnsHotSubset(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, fullConfig)

	rt, err := config.LoadRuntime(path)
	require.NoError(t, err)
	require.Equal(t, config.ModeEnforce, rt.Mode)
	require.False(t, rt.FailClosed)
	require.Equal(t, []string{"IR", "KP", "RU"}, rt.Countries)
	require.Equal(t, []string{"UA-09", "UA-14"}, rt.Regions)
}

func TestLoadRuntime_InvalidModeRejected(t *testing.T) {
	t.Parallel()

	path := writeConfig(t, "mode: nonsense\n")

	_, err := config.LoadRuntime(path)
	require.ErrorIs(t, err, config.ErrInvalidMode)
}

func TestRuntimeFingerprint(t *testing.T) {
	t.Parallel()

	base := config.Runtime{
		Mode:       config.ModeEnforce,
		FailClosed: true,
		Countries:  []string{"IR", "KP"},
		Regions:    []string{"UA-43"},
	}

	// Order- and case-independent over the lists.
	reordered := config.Runtime{
		Mode:       config.ModeEnforce,
		FailClosed: true,
		Countries:  []string{"kp", " ir "},
		Regions:    []string{"ua-43"},
	}
	require.Equal(t, base.Fingerprint(), reordered.Fingerprint(),
		"fingerprint must be order- and case-independent")

	// Each material field changes the fingerprint.
	modeChanged := base
	modeChanged.Mode = config.ModeDetect
	require.NotEqual(t, base.Fingerprint(), modeChanged.Fingerprint(), "mode change must show")

	fcChanged := base
	fcChanged.FailClosed = false
	require.NotEqual(t, base.Fingerprint(), fcChanged.Fingerprint(), "fail-closed change must show")

	listChanged := base
	listChanged.Countries = []string{"IR", "KP", "RU"}
	require.NotEqual(t, base.Fingerprint(), listChanged.Fingerprint(), "list change must show")
}

func TestConfigFilePath(t *testing.T) {
	// Not parallel: mutates process environment.
	t.Setenv("GEOIP_CONFIG_FILE", "")
	require.Equal(t, config.DefaultConfigFile, config.ConfigFilePath())

	t.Setenv("GEOIP_CONFIG_FILE", "/custom/path.yaml")
	require.Equal(t, "/custom/path.yaml", config.ConfigFilePath())
}
