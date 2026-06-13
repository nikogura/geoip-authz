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
	"strings"
	"sync/atomic"
)

// Reason codes surfaced in the verdict.
const (
	// ReasonAllowed indicates the client is permitted.
	ReasonAllowed = "allowed"
	// ReasonBlockedCountry indicates the client's country is blocklisted.
	ReasonBlockedCountry = "blocked-country"
	// ReasonBlockedRegion indicates the client's region is blocklisted.
	ReasonBlockedRegion = "blocked-region"
	// ReasonLookupFailed is fail-closed: no usable geo data for the client.
	ReasonLookupFailed = "lookup-failed"
	// ReasonNoClientAddress is fail-closed: client IP missing or unparseable.
	ReasonNoClientAddress = "no-client-address"
)

// Verdict is the outcome of a blocklist decision.
type Verdict struct {
	// Blocked is true when the client must be denied (in enforce mode).
	Blocked bool
	// Reason is a short machine-readable cause, surfaced in logs/headers.
	Reason string
	// CountryISO is the resolved ISO-3166-1 alpha-2 country code ("" if none).
	CountryISO string
	// RegionISO is the resolved "<country>-<subdivision>" code ("" if none).
	RegionISO string
}

// blocklistSets is the immutable country/region policy snapshot held behind an
// atomic pointer so the whole policy can be hot-swapped in one store, with no
// lock on the read path.
type blocklistSets struct {
	countries map[string]struct{}
	regions   map[string]struct{}
}

// Blocklist holds the operator-supplied country/region policy and the
// fail-closed behaviour. Both are swappable at runtime via Replace (the sets
// behind an atomic pointer, fail-closed behind an atomic bool), so the whole
// policy can be hot-reloaded without restarting the process. Safe for
// concurrent use.
type Blocklist struct {
	sets       atomic.Pointer[blocklistSets]
	failClosed atomic.Bool
}

// NewBlocklist builds a Blocklist from lists of ISO-3166-1 alpha-2 country
// codes and ISO-3166-2 "<country>-<subdivision>" region codes. Entries are
// upper-cased and trimmed. failClosed controls whether un-locatable clients are
// denied.
func NewBlocklist(countries, regions []string, failClosed bool) (b *Blocklist) {
	b = &Blocklist{}
	b.Replace(countries, regions, failClosed)

	return b
}

// Replace atomically swaps the country/region policy and the fail-closed
// behaviour. It is safe to call concurrently with Decide/Evaluate: in-flight
// decisions complete against the previous snapshot and subsequent decisions see
// the new one. fail-closed is swapped too so a hot-reload can flip it without a
// restart.
func (b *Blocklist) Replace(countries, regions []string, failClosed bool) {
	b.sets.Store(&blocklistSets{
		countries: toSet(countries),
		regions:   toSet(regions),
	})
	b.failClosed.Store(failClosed)
}

// Sizes returns the current count of blocked countries and regions, for
// instrumentation.
func (b *Blocklist) Sizes() (countries, regions int) {
	current := b.sets.Load()
	countries = len(current.countries)
	regions = len(current.regions)

	return countries, regions
}

// toSet normalises a list into an upper-cased, trimmed set.
func toSet(items []string) (set map[string]struct{}) {
	set = make(map[string]struct{}, len(items))
	for _, item := range items {
		key := strings.ToUpper(strings.TrimSpace(item))
		if key != "" {
			set[key] = struct{}{}
		}
	}

	return set
}

// Decide applies the blocklist to a resolved country and subdivision. An empty
// country means the lookup yielded no usable data; the result then depends on
// the fail-closed setting.
//
// country is the ISO-3166-1 alpha-2 code; subdivision is the bare ISO-3166-2
// subdivision suffix (e.g. "43" for Crimea), as emitted by the GeoLite2 City
// database. Both are upper-cased defensively.
func (b *Blocklist) Decide(country, subdivision string) (v Verdict) {
	country = strings.ToUpper(strings.TrimSpace(country))
	subdivision = strings.ToUpper(strings.TrimSpace(subdivision))

	if country == "" {
		v = Verdict{Blocked: b.failClosed.Load(), Reason: ReasonLookupFailed}

		return v
	}

	region := country + "-" + subdivision

	v = Verdict{
		Blocked:    false,
		Reason:     ReasonAllowed,
		CountryISO: country,
		RegionISO:  region,
	}

	current := b.sets.Load()

	if _, blocked := current.countries[country]; blocked {
		v.Blocked = true
		v.Reason = ReasonBlockedCountry

		return v
	}

	if _, blocked := current.regions[region]; blocked {
		v.Blocked = true
		v.Reason = ReasonBlockedRegion

		return v
	}

	return v
}
