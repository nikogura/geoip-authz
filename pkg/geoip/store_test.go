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
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/stretchr/testify/require"
)

// makeTarGz builds a gzip-compressed tar containing the given files.
func makeTarGz(t *testing.T, files map[string][]byte) (out []byte) {
	t.Helper()

	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)

	for name, content := range files {
		hdr := &tar.Header{Name: name, Mode: 0o600, Size: int64(len(content)), Typeflag: tar.TypeReg}

		err := tw.WriteHeader(hdr)
		require.NoError(t, err)

		_, err = tw.Write(content)
		require.NoError(t, err)
	}

	require.NoError(t, tw.Close())
	require.NoError(t, gz.Close())

	out = buf.Bytes()

	return out
}

func TestStore_ResolveBeforeLoadFailsClosed(t *testing.T) {
	t.Parallel()

	store := geoip.NewStore(nil)
	require.False(t, store.Ready())

	_, err := store.Resolve(net.ParseIP("8.8.8.8"))
	require.ErrorIs(t, err, geoip.ErrNoDatabase)
}

func TestStore_LoadBytesRejectsInvalidDatabase(t *testing.T) {
	t.Parallel()

	store := geoip.NewStore(nil)

	err := store.LoadBytes([]byte("not a real mmdb"))
	require.Error(t, err)
	require.False(t, store.Ready(), "store must stay unready after a failed load")
}

func TestStore_FetchNon200LeavesLastGood(t *testing.T) {
	t.Parallel()

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer srv.Close()

	store := geoip.NewStore(srv.Client())

	err := store.Fetch(context.Background(), srv.URL, "123", "key")
	require.Error(t, err)
	require.False(t, store.Ready())
}

func TestStore_FetchForwardsBasicAuthAndExtracts(t *testing.T) {
	t.Parallel()

	var gotUser, gotPass string
	var gotOK bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotUser, gotPass, gotOK = r.BasicAuth()
		// A well-formed archive with bogus mmdb bytes: exercises the auth +
		// extract path; LoadBytes then fails to parse (past the code under test).
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeTarGz(t, map[string][]byte{
			"GeoLite2-City_x/GeoLite2-City.mmdb": []byte("bogus"),
		}))
	}))
	defer srv.Close()

	store := geoip.NewStore(srv.Client())
	_ = store.Fetch(context.Background(), srv.URL, "123456", "license-abc")

	require.True(t, gotOK)
	require.Equal(t, "123456", gotUser)
	require.Equal(t, "license-abc", gotPass)
}

// MaxMind credentials are optional: with both empty, no Authorization header is
// sent (supports unauthenticated mirrors, credential-injecting proxies, or
// GEOIP_DB_PATH-only deployments).
func TestStore_FetchOmitsAuthWhenCredsEmpty(t *testing.T) {
	t.Parallel()

	var sawAuth bool

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _, sawAuth = r.BasicAuth()
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(makeTarGz(t, map[string][]byte{"GeoLite2-City_x/GeoLite2-City.mmdb": []byte("bogus")}))
	}))
	defer srv.Close()

	store := geoip.NewStore(srv.Client())
	_ = store.Fetch(context.Background(), srv.URL, "", "")

	require.False(t, sawAuth, "no basic-auth header should be sent when creds are empty")
}
