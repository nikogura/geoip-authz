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

package geoip_test

import (
	"errors"
	"net"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/stretchr/testify/require"
)

// fakeResolver is a test double letting blocklist behaviour be exercised
// without a real database.
type fakeResolver struct {
	res geoip.GeoResult
	err error
}

func (f fakeResolver) Resolve(_ net.IP) (res geoip.GeoResult, err error) {
	res = f.res
	err = f.err

	return res, err
}

func TestEvaluate_NilIPFailsClosed(t *testing.T) {
	t.Parallel()

	closed := geoip.NewBlocklist(nil, nil, true)
	v := closed.Evaluate(fakeResolver{res: geoip.GeoResult{CountryISO: "US"}}, nil)
	require.True(t, v.Blocked)
	require.Equal(t, geoip.ReasonNoClientAddress, v.Reason)

	open := geoip.NewBlocklist(nil, nil, false)
	require.False(t, open.Evaluate(fakeResolver{}, nil).Blocked)
}

func TestEvaluate_ResolverErrorFailsClosed(t *testing.T) {
	t.Parallel()

	closed := geoip.NewBlocklist(nil, nil, true)
	v := closed.Evaluate(fakeResolver{err: errors.New("boom")}, net.ParseIP("8.8.8.8"))
	require.True(t, v.Blocked)
	require.Equal(t, geoip.ReasonLookupFailed, v.Reason)
}

func TestEvaluate_BlockedAndAllowed(t *testing.T) {
	t.Parallel()

	b := geoip.NewBlocklist([]string{"RU"}, []string{"UA-43"}, true)

	country := b.Evaluate(fakeResolver{res: geoip.GeoResult{CountryISO: "RU"}}, net.ParseIP("5.5.5.5"))
	require.True(t, country.Blocked)
	require.Equal(t, geoip.ReasonBlockedCountry, country.Reason)

	region := b.Evaluate(fakeResolver{res: geoip.GeoResult{CountryISO: "UA", SubdivisionISO: "43"}}, net.ParseIP("5.5.5.6"))
	require.True(t, region.Blocked)
	require.Equal(t, geoip.ReasonBlockedRegion, region.Reason)

	clean := b.Evaluate(fakeResolver{res: geoip.GeoResult{CountryISO: "US", SubdivisionISO: "CA"}}, net.ParseIP("8.8.8.8"))
	require.False(t, clean.Blocked)
}
