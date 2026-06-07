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

// Package config resolves geoip-authz runtime configuration from the
// environment (GEOIP_ prefix). The blocklist and database source are
// configuration, not code, so the service stays policy-neutral and reusable.
package config

import (
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"time"
)

// Mode controls whether the service blocks (enforce) or only annotates and
// logs the verdict (detect). Detect always returns HTTP 200 so it can run in
// the request path without affecting traffic during validation.
type Mode string

const (
	// ModeDetect logs the would-block verdict but always allows the request.
	ModeDetect Mode = "detect"
	// ModeEnforce returns 403 for blocked clients.
	ModeEnforce Mode = "enforce"
)

const (
	envPrefix = "GEOIP_"

	defaultListenAddr           = ":8080"
	defaultDownloadURL          = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
	defaultRefreshEvery         = 24 * time.Hour
	defaultClientIPHeader       = "X-Forwarded-For"
	defaultHTTPTimeout          = 60 * time.Second
	defaultFailClosed           = true
	defaultBlocklistReloadEvery = 30 * time.Second
)

// ErrInvalidMode is returned when GEOIP_MODE is neither detect nor enforce.
var ErrInvalidMode = errors.New("invalid mode: must be 'detect' or 'enforce'")

// Config is the fully-resolved service configuration.
type Config struct {
	// ListenAddr is the address the HTTP server binds (ext_authz + health).
	ListenAddr string
	// Mode is detect or enforce.
	Mode Mode
	// DownloadURL is the GeoLite2-City tar.gz endpoint. Defaults to MaxMind;
	// point it at a caching mirror to avoid hitting MaxMind from every replica.
	DownloadURL string
	// AccountID is the MaxMind account ID used for basic-auth to the download.
	AccountID string
	// LicenseKey is the MaxMind license key used for basic-auth to the download.
	LicenseKey string
	// RefreshEvery is how often the database is re-pulled.
	RefreshEvery time.Duration
	// HTTPTimeout bounds the database download request.
	HTTPTimeout time.Duration
	// ClientIPHeader is the request header carrying the client IP (default
	// X-Forwarded-For). The left-most address is used.
	ClientIPHeader string
	// DBPath, when set, loads a local .mmdb instead of downloading.
	DBPath string
	// BlockedCountries is the ISO-3166-1 alpha-2 country blocklist.
	BlockedCountries []string
	// BlockedRegions is the ISO-3166-2 "<country>-<subdivision>" region
	// blocklist (needs the GeoLite2-City database for subdivision granularity).
	BlockedRegions []string
	// BlocklistDir, when set, loads the country/region blocklist from files
	// ("countries" and "regions") in this directory and HOT-RELOADS them on a
	// timer. Mount a ConfigMap here so a compliance edit takes effect without a
	// pod restart. When set, it takes precedence over the env-supplied
	// BlockedCountries/BlockedRegions (which can't change in a running container).
	BlocklistDir string
	// BlocklistReloadEvery is how often BlocklistDir is re-read for changes.
	BlocklistReloadEvery time.Duration
	// FailClosed denies (rather than allows) when the client location can't be
	// determined: missing/unparseable IP, lookup error, or DB not yet loaded.
	FailClosed bool
}

// Load resolves the configuration from the environment, applying defaults.
func Load() (cfg Config, err error) {
	cfg = Config{
		ListenAddr:       getEnv("LISTEN_ADDR", defaultListenAddr),
		Mode:             Mode(strings.ToLower(getEnv("MODE", string(ModeDetect)))),
		DownloadURL:      getEnv("DOWNLOAD_URL", defaultDownloadURL),
		AccountID:        getEnv("ACCOUNT_ID", ""),
		LicenseKey:       getEnv("LICENSE_KEY", ""),
		ClientIPHeader:   getEnv("CLIENT_IP_HEADER", defaultClientIPHeader),
		DBPath:           getEnv("DB_PATH", ""),
		BlockedCountries: getEnvList("BLOCKED_COUNTRIES"),
		BlockedRegions:   getEnvList("BLOCKED_REGIONS"),
		BlocklistDir:     getEnv("BLOCKLIST_DIR", ""),
		FailClosed:       getEnvBool("FAIL_CLOSED", defaultFailClosed),
	}

	cfg.RefreshEvery, err = getEnvDuration("REFRESH_EVERY", defaultRefreshEvery)
	if err != nil {
		return cfg, err
	}

	cfg.HTTPTimeout, err = getEnvDuration("HTTP_TIMEOUT", defaultHTTPTimeout)
	if err != nil {
		return cfg, err
	}

	cfg.BlocklistReloadEvery, err = getEnvDuration("BLOCKLIST_RELOAD_EVERY", defaultBlocklistReloadEvery)
	if err != nil {
		return cfg, err
	}

	err = cfg.validate()
	if err != nil {
		return cfg, err
	}

	return cfg, err
}

// validate checks the resolved configuration for internal consistency.
func (c Config) validate() (err error) {
	if c.Mode != ModeDetect && c.Mode != ModeEnforce {
		err = fmt.Errorf("%w: got %q", ErrInvalidMode, c.Mode)

		return err
	}

	return err
}

// getEnv reads GEOIP_<key>, falling back to def when unset or empty.
func getEnv(key, def string) (val string) {
	val = os.Getenv(envPrefix + key)
	if val == "" {
		val = def
	}

	return val
}

// getEnvList reads GEOIP_<key> as a list separated by commas and/or newlines,
// so both inline (`IR,KP,RU`) and YAML block-scalar (`|`) forms work:
//
//	GEOIP_BLOCKED_COUNTRIES: |
//	  IR
//	  KP
//	  RU
//
// Entries are trimmed; empties are dropped. Returns an empty slice when unset.
func getEnvList(key string) (out []string) {
	raw := os.Getenv(envPrefix + key)
	out = []string{}

	if raw == "" {
		return out
	}

	fields := strings.FieldsFunc(raw, func(r rune) (sep bool) {
		sep = r == ',' || r == '\n' || r == '\r'

		return sep
	})

	for _, item := range fields {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

// getEnvBool reads GEOIP_<key> as a bool, falling back to def when unset or
// unparseable.
func getEnvBool(key string, def bool) (val bool) {
	val = def

	raw := os.Getenv(envPrefix + key)
	if raw == "" {
		return val
	}

	parsed, err := strconv.ParseBool(raw)
	if err != nil {
		return val
	}

	val = parsed

	return val
}

// getEnvDuration reads GEOIP_<key> as a Go duration, falling back to def.
func getEnvDuration(key string, def time.Duration) (d time.Duration, err error) {
	raw := os.Getenv(envPrefix + key)
	if raw == "" {
		d = def

		return d, err
	}

	d, err = time.ParseDuration(raw)
	if err != nil {
		err = fmt.Errorf("parsing %s%s: %w", envPrefix, key, err)
		d = def

		return d, err
	}

	return d, err
}

// ParseAccountID converts the MaxMind account ID string to an int, tolerating
// an empty value (returns 0).
func ParseAccountID(raw string) (id int, err error) {
	if raw == "" {
		return id, err
	}

	id, err = strconv.Atoi(raw)
	if err != nil {
		err = fmt.Errorf("parsing account id: %w", err)
		id = 0

		return id, err
	}

	return id, err
}
