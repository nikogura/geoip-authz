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

func TestLoad_BlocklistDirDefaults(t *testing.T) {
	t.Setenv("GEOIP_BLOCKLIST_DIR", "")
	t.Setenv("GEOIP_BLOCKLIST_RELOAD_EVERY", "")

	cfg, err := config.Load()
	require.NoError(t, err)
	require.Empty(t, cfg.BlocklistDir, "no dir configured by default (env-list mode)")
	require.Equal(t, 30*time.Second, cfg.BlocklistReloadEvery, "default reload interval")
}

func TestLoad_BlocklistDirAndReloadEvery(t *testing.T) {
	t.Setenv("GEOIP_BLOCKLIST_DIR", "/etc/geoip-authz/blocklist")
	t.Setenv("GEOIP_BLOCKLIST_RELOAD_EVERY", "15s")

	cfg, err := config.Load()
	require.NoError(t, err)
	require.Equal(t, "/etc/geoip-authz/blocklist", cfg.BlocklistDir)
	require.Equal(t, 15*time.Second, cfg.BlocklistReloadEvery)
}
