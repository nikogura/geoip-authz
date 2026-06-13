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

// Package config resolves geoip-authz runtime configuration from a single
// YAML config file (file-authoritative). The blocklist, mode, and fail-closed
// behaviour are configuration, not code, so the service stays policy-neutral
// and reusable. The hot-reloadable subset (mode, fail-closed, blocklist) is
// re-read on a timer so a compliance edit takes effect without a pod restart.
//
// The MaxMind credentials are the only exception to "file-authoritative": they
// are injected from the environment (GEOIP_ACCOUNT_ID / GEOIP_LICENSE_KEY) so a
// secret never lives in a ConfigMap. The config file path itself comes from
// GEOIP_CONFIG_FILE.
package config

import (
	"errors"
	"fmt"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
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
	// envPrefix namespaces the few remaining environment inputs: the config
	// file path and the MaxMind secret credentials.
	envPrefix = "GEOIP_"

	// DefaultConfigFile is read when GEOIP_CONFIG_FILE is unset. Mount the
	// unified ConfigMap (key "config.yaml") at this path.
	DefaultConfigFile = "/etc/geoip-authz/config.yaml"

	defaultListenAddr     = ":8080"
	defaultDownloadURL    = "https://download.maxmind.com/geoip/databases/GeoLite2-City/download?suffix=tar.gz"
	defaultRefreshEvery   = 24 * time.Hour
	defaultClientIPHeader = "X-Forwarded-For"
	defaultHTTPTimeout    = 60 * time.Second
	defaultReloadEvery    = 30 * time.Second
	defaultFailClosed     = true
)

// ErrInvalidMode is returned when mode is neither detect nor enforce.
var ErrInvalidMode = errors.New("invalid mode: must be 'detect' or 'enforce'")

// StringList is a list of strings that unmarshals from EITHER a YAML scalar /
// block scalar (split on commas and/or newlines, so a `|` block stays
// one-entry-per-line and readable) OR a real YAML sequence. Entries are
// trimmed; empties dropped. This keeps the blocklist's original file ergonomics
// while living inside the unified config file.
type StringList []string

// UnmarshalYAML accepts both the scalar (comma/newline-separated) and the
// sequence forms.
func (s *StringList) UnmarshalYAML(value *yaml.Node) (err error) {
	// A scalar (including a `|` block) is split on commas/newlines so a block
	// stays one-entry-per-line and readable.
	if value.Kind == yaml.ScalarNode {
		*s = StringList(splitList(value.Value))

		return err
	}

	// A real YAML sequence is decoded and trimmed.
	if value.Kind == yaml.SequenceNode {
		var items []string

		err = value.Decode(&items)
		if err != nil {
			err = fmt.Errorf("decoding list sequence: %w", err)

			return err
		}

		*s = StringList(trimDrop(items))

		return err
	}

	err = fmt.Errorf("list must be a scalar block or sequence, got yaml kind %d", value.Kind)

	return err
}

// Duration wraps time.Duration so a YAML value like "30s" parses via
// time.ParseDuration (yaml.v3 otherwise expects an integer nanosecond count).
type Duration time.Duration

// UnmarshalYAML parses a Go duration string (e.g. "30s", "24h").
func (d *Duration) UnmarshalYAML(value *yaml.Node) (err error) {
	var parsed time.Duration

	parsed, err = time.ParseDuration(strings.TrimSpace(value.Value))
	if err != nil {
		err = fmt.Errorf("parsing duration %q: %w", value.Value, err)

		return err
	}

	*d = Duration(parsed)

	return err
}

// Blocklist is the country/region policy section of the config file.
type Blocklist struct {
	// Countries is the ISO-3166-1 alpha-2 country blocklist.
	Countries StringList `yaml:"countries"`
	// Regions is the ISO-3166-2 "<country>-<subdivision>" region blocklist
	// (needs the GeoLite2-City database for subdivision granularity).
	Regions StringList `yaml:"regions"`
}

// fileConfig is the on-disk YAML shape. It is deliberately separate from the
// resolved Config so optional fields can default safely — notably failClosed,
// whose safe default is true and so cannot be a plain bool (which would make an
// omitted value mean false).
type fileConfig struct {
	ListenAddr     string    `yaml:"listenAddr"`
	DownloadURL    string    `yaml:"geoDownloadURL"`
	RefreshEvery   *Duration `yaml:"refreshEvery"`
	HTTPTimeout    *Duration `yaml:"httpTimeout"`
	ClientIPHeader string    `yaml:"clientIPHeader"`
	DBPath         string    `yaml:"dbPath"`
	ReloadEvery    *Duration `yaml:"reloadEvery"`
	Mode           Mode      `yaml:"mode"`
	FailClosed     *bool     `yaml:"failClosed"`
	Blocklist      Blocklist `yaml:"blocklist"`
}

// Config is the fully-resolved service configuration.
type Config struct {
	// --- boot config (from the file; a change requires a restart) ---

	// ListenAddr is the address the HTTP server binds (ext_authz + health).
	ListenAddr string
	// DownloadURL is the GeoLite2-City tar.gz endpoint. Point it at a caching
	// mirror so replicas do not each hit MaxMind.
	DownloadURL string
	// RefreshEvery is how often the database is re-pulled.
	RefreshEvery time.Duration
	// HTTPTimeout bounds the database download request.
	HTTPTimeout time.Duration
	// ClientIPHeader carries the client IP (default X-Forwarded-For); the
	// left-most address is used.
	ClientIPHeader string
	// DBPath, when set, loads a local .mmdb instead of downloading.
	DBPath string
	// ReloadEvery is how often the config file is re-read for the
	// hot-reloadable subset (mode, fail-closed, blocklist).
	ReloadEvery time.Duration

	// --- hot-reloadable config (from the file; re-read on ReloadEvery) ---

	// Mode is detect or enforce.
	Mode Mode
	// FailClosed denies (rather than allows) when the client location cannot be
	// determined: missing/unparseable IP, lookup error, or DB not yet loaded.
	FailClosed bool
	// BlockedCountries is the resolved ISO-3166-1 alpha-2 country blocklist.
	BlockedCountries []string
	// BlockedRegions is the resolved ISO-3166-2 region blocklist.
	BlockedRegions []string

	// --- secrets (env-injected from the Vault Secret; never in the file) ---

	// AccountID is the MaxMind account ID used for basic-auth to the download.
	AccountID string
	// LicenseKey is the MaxMind license key used for basic-auth to the download.
	LicenseKey string

	// ConfigFile is the path this config was loaded from (used for hot-reload).
	ConfigFile string
}

// Runtime is the hot-reloadable subset of configuration. The reload loop
// re-reads the config file into a Runtime, validates it, and atomically swaps
// it in — boot fields are intentionally excluded because they cannot change in
// a running process.
type Runtime struct {
	// Mode is detect or enforce.
	Mode Mode
	// FailClosed denies un-locatable clients when true.
	FailClosed bool
	// Countries is the resolved country blocklist.
	Countries []string
	// Regions is the resolved region blocklist.
	Regions []string
}

// Fingerprint is an order-independent signature of the runtime policy, used to
// skip redundant swaps when a reload sees no change (so an unchanged ConfigMap
// projection does not churn the live policy or spam events).
func (r Runtime) Fingerprint() (sig string) {
	sig = string(r.Mode) +
		";fail_closed=" + strconv.FormatBool(r.FailClosed) +
		";countries=" + canonical(r.Countries) +
		";regions=" + canonical(r.Regions)

	return sig
}

// ConfigFilePath returns the config file path from GEOIP_CONFIG_FILE, falling
// back to DefaultConfigFile.
func ConfigFilePath() (path string) {
	path = getEnv("CONFIG_FILE", DefaultConfigFile)

	return path
}

// LoadFile resolves the full configuration from the YAML file at path, applies
// defaults, overlays the env-supplied secret credentials, and validates.
func LoadFile(path string) (cfg Config, err error) {
	var resolved Config

	resolved, err = readConfig(path)
	if err != nil {
		return cfg, err
	}

	cfg = resolved
	cfg.AccountID = getEnv("ACCOUNT_ID", "")
	cfg.LicenseKey = getEnv("LICENSE_KEY", "")
	cfg.ConfigFile = path

	err = cfg.validate()
	if err != nil {
		return cfg, err
	}

	return cfg, err
}

// LoadRuntime re-reads only the hot-reloadable subset from the file at path and
// validates it. Used by the reload loop; it never touches secrets or boot
// fields.
func LoadRuntime(path string) (rt Runtime, err error) {
	var cfg Config

	cfg, err = readConfig(path)
	if err != nil {
		return rt, err
	}

	rt = Runtime{
		Mode:       cfg.Mode,
		FailClosed: cfg.FailClosed,
		Countries:  cfg.BlockedCountries,
		Regions:    cfg.BlockedRegions,
	}

	err = rt.validate()
	if err != nil {
		return rt, err
	}

	return rt, err
}

// readConfig reads and parses the YAML file and applies defaults, without
// touching secrets, the source path, or validation.
func readConfig(path string) (cfg Config, err error) {
	var raw []byte

	raw, err = os.ReadFile(path) //nolint:gosec // path is operator-configured, not user input
	if err != nil {
		err = fmt.Errorf("reading config file %q: %w", path, err)

		return cfg, err
	}

	var fc fileConfig

	err = yaml.Unmarshal(raw, &fc)
	if err != nil {
		err = fmt.Errorf("parsing config file %q: %w", path, err)

		return cfg, err
	}

	cfg = resolve(fc)

	return cfg, err
}

// resolve turns the optional on-disk shape into a fully-defaulted Config.
func resolve(fc fileConfig) (cfg Config) {
	cfg = Config{
		ListenAddr:       firstNonEmpty(fc.ListenAddr, defaultListenAddr),
		DownloadURL:      firstNonEmpty(fc.DownloadURL, defaultDownloadURL),
		RefreshEvery:     durationOr(fc.RefreshEvery, defaultRefreshEvery),
		HTTPTimeout:      durationOr(fc.HTTPTimeout, defaultHTTPTimeout),
		ClientIPHeader:   firstNonEmpty(fc.ClientIPHeader, defaultClientIPHeader),
		DBPath:           fc.DBPath,
		ReloadEvery:      durationOr(fc.ReloadEvery, defaultReloadEvery),
		Mode:             Mode(strings.ToLower(strings.TrimSpace(string(fc.Mode)))),
		FailClosed:       boolOr(fc.FailClosed, defaultFailClosed),
		BlockedCountries: trimDrop(fc.Blocklist.Countries),
		BlockedRegions:   trimDrop(fc.Blocklist.Regions),
	}

	if cfg.Mode == "" {
		cfg.Mode = ModeDetect
	}

	return cfg
}

// validate checks the resolved configuration for internal consistency.
func (c Config) validate() (err error) {
	if c.Mode != ModeDetect && c.Mode != ModeEnforce {
		err = fmt.Errorf("%w: got %q", ErrInvalidMode, c.Mode)

		return err
	}

	return err
}

// validate checks the hot-reloadable subset. The mode check is what stops a
// fat-fingered edit (e.g. "block") from being swapped in over a good policy.
func (r Runtime) validate() (err error) {
	if r.Mode != ModeDetect && r.Mode != ModeEnforce {
		err = fmt.Errorf("%w: got %q", ErrInvalidMode, r.Mode)

		return err
	}

	return err
}

// splitList splits a comma/newline/CR-separated string, trimming entries and
// dropping empties. This is the forgiving list format shared by the YAML block
// scalars so a `|` block reads one-entry-per-line.
func splitList(raw string) (out []string) {
	out = []string{}

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

// trimDrop trims each entry and drops empties, preserving order.
func trimDrop(items []string) (out []string) {
	out = []string{}
	for _, item := range items {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out
}

// canonical normalises a list to a sorted, upper-cased, comma-joined string for
// fingerprinting.
func canonical(items []string) (out string) {
	norm := make([]string, 0, len(items))
	for _, item := range items {
		trimmed := strings.ToUpper(strings.TrimSpace(item))
		if trimmed != "" {
			norm = append(norm, trimmed)
		}
	}

	sort.Strings(norm)

	out = strings.Join(norm, ",")

	return out
}

// firstNonEmpty returns val when non-empty, else def.
func firstNonEmpty(val, def string) (out string) {
	out = val
	if strings.TrimSpace(out) == "" {
		out = def
	}

	return out
}

// durationOr returns *d when set, else def.
func durationOr(d *Duration, def time.Duration) (out time.Duration) {
	out = def
	if d != nil {
		out = time.Duration(*d)
	}

	return out
}

// boolOr returns *b when set, else def.
func boolOr(b *bool, def bool) (out bool) {
	out = def
	if b != nil {
		out = *b
	}

	return out
}

// getEnv reads GEOIP_<key>, falling back to def when unset or empty.
func getEnv(key, def string) (val string) {
	val = os.Getenv(envPrefix + key)
	if val == "" {
		val = def
	}

	return val
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
