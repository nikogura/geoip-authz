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

import "net"

// GeoResult is the geolocation of a client IP needed for the blocklist
// decision.
type GeoResult struct {
	// CountryISO is the ISO-3166-1 alpha-2 country code.
	CountryISO string
	// SubdivisionISO is the bare ISO-3166-2 subdivision suffix (e.g. "43").
	SubdivisionISO string
}

// Resolver maps a client IP to a GeoResult. Implementations must be safe for
// concurrent use. A non-nil error means the lookup could not be performed and
// the caller must fail closed.
type Resolver interface {
	Resolve(ip net.IP) (res GeoResult, err error)
}

// Evaluate resolves an IP and applies the blocklist, honouring the fail-closed
// setting on any resolution error. It is the single decision entry point used
// by the controller.
func (b *Blocklist) Evaluate(r Resolver, ip net.IP) (v Verdict) {
	if ip == nil {
		v = Verdict{Blocked: b.failClosed, Reason: ReasonNoClientAddress}

		return v
	}

	res, err := r.Resolve(ip)
	if err != nil {
		v = Verdict{Blocked: b.failClosed, Reason: ReasonLookupFailed}

		return v
	}

	v = b.Decide(res.CountryISO, res.SubdivisionISO)

	return v
}
