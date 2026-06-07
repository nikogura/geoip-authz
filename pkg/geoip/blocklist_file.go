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

package geoip

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Blocklist directory file names. Mounting a ConfigMap with these keys makes the
// policy a set of files the kubelet updates in place, enabling hot-reload.
const (
	// FileCountries holds the country blocklist (one entry per line / comma).
	FileCountries = "countries"
	// FileRegions holds the region blocklist (one entry per line / comma).
	FileRegions = "regions"
)

// LoadBlocklistFiles reads the country and region blocklists from dir, expecting
// files named "countries" and "regions". Each file is a list separated by
// commas and/or newlines (the same forgiving format as the env vars), so a YAML
// block scalar mounted as a file stays readable. A missing file yields an empty
// list rather than an error, so a partially-populated ConfigMap is tolerated;
// any other read error is returned.
func LoadBlocklistFiles(dir string) (countries, regions []string, err error) {
	countries, err = readListFile(filepath.Join(dir, FileCountries))
	if err != nil {
		err = fmt.Errorf("reading country blocklist: %w", err)

		return countries, regions, err
	}

	regions, err = readListFile(filepath.Join(dir, FileRegions))
	if err != nil {
		err = fmt.Errorf("reading region blocklist: %w", err)

		return countries, regions, err
	}

	return countries, regions, err
}

// Fingerprint is a stable, order-independent signature of a country/region
// blocklist pair, used to detect whether a reload actually changed the policy
// (so an unchanged ConfigMap projection doesn't churn the live blocklist).
func Fingerprint(countries, regions []string) (sig string) {
	sig = canonical(countries) + "|" + canonical(regions)

	return sig
}

// canonical normalises a list to a sorted, upper-cased, comma-joined string.
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

// readListFile reads a comma/newline-separated list file. A non-existent file is
// treated as an empty list (not an error).
func readListFile(path string) (out []string, err error) {
	out = []string{}

	var raw []byte

	raw, err = os.ReadFile(path) //nolint:gosec // path is operator-configured mount, not user input
	if err != nil {
		if os.IsNotExist(err) {
			err = nil

			return out, err
		}

		return out, err
	}

	fields := strings.FieldsFunc(string(raw), func(r rune) (sep bool) {
		sep = r == ',' || r == '\n' || r == '\r'

		return sep
	})

	for _, item := range fields {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out = append(out, trimmed)
		}
	}

	return out, err
}
