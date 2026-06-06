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
	"archive/tar"
	"compress/gzip"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"strings"
	"sync/atomic"

	"github.com/oschwald/geoip2-golang"
)

// maxDBBytes caps the in-memory database to guard against a malformed or
// hostile download (the real GeoLite2-City db is ~60-70 MB).
const maxDBBytes = 256 << 20 // 256 MiB

// ErrNoDatabase is returned by Resolve before any database has been loaded.
// It causes the caller to fail closed.
var ErrNoDatabase = errors.New("geoip database not loaded")

// ErrNoMMDBInArchive is returned when the downloaded tar.gz contains no .mmdb.
var ErrNoMMDBInArchive = errors.New("no .mmdb entry found in archive")

// Store holds the active GeoLite2-City reader behind an atomic pointer so the
// database can be swapped at runtime without locking the request path. It
// implements Resolver. The zero value is not usable; construct with NewStore.
type Store struct {
	reader atomic.Pointer[geoip2.Reader]
	client *http.Client
}

// NewStore creates an empty Store. Until a database is loaded (LoadBytes,
// LoadFile, or Fetch) every Resolve fails closed.
func NewStore(client *http.Client) (s *Store) {
	if client == nil {
		client = http.DefaultClient
	}

	s = &Store{client: client}

	return s
}

// Ready reports whether a database is loaded and the service can serve
// authoritative verdicts.
func (s *Store) Ready() (ready bool) {
	ready = s.reader.Load() != nil

	return ready
}

// Resolve implements Resolver. It fails closed (returns an error) when no
// database is loaded yet.
func (s *Store) Resolve(ip net.IP) (res GeoResult, err error) {
	reader := s.reader.Load()
	if reader == nil {
		err = ErrNoDatabase

		return res, err
	}

	var city *geoip2.City

	city, err = reader.City(ip)
	if err != nil {
		err = fmt.Errorf("geoip city lookup: %w", err)

		return res, err
	}

	res = GeoResult{CountryISO: city.Country.IsoCode}
	if len(city.Subdivisions) > 0 {
		res.SubdivisionISO = city.Subdivisions[0].IsoCode
	}

	return res, err
}

// LoadBytes parses an .mmdb byte slice and atomically swaps it in as the active
// database. The previous reader (if any) is closed.
func (s *Store) LoadBytes(db []byte) (err error) {
	var reader *geoip2.Reader

	reader, err = geoip2.FromBytes(db)
	if err != nil {
		err = fmt.Errorf("opening mmdb: %w", err)

		return err
	}

	old := s.reader.Swap(reader)
	if old != nil {
		_ = old.Close()
	}

	return err
}

// LoadFile reads an .mmdb file from disk and swaps it in. Used for local
// bring-up and tests via GEOIP_DB_PATH.
func (s *Store) LoadFile(path string) (err error) {
	var db []byte

	db, err = os.ReadFile(path) //nolint:gosec // path is operator-supplied config, not user input
	if err != nil {
		err = fmt.Errorf("reading mmdb file: %w", err)

		return err
	}

	err = s.LoadBytes(db)

	return err
}

// Fetch downloads the GeoLite2-City tar.gz from url, authenticating with the
// MaxMind account ID / license key via HTTP basic auth, extracts the .mmdb, and
// swaps it in. On any error the currently-loaded database is left untouched
// (last-good is retained).
func (s *Store) Fetch(ctx context.Context, url, accountID, licenseKey string) (err error) {
	var req *http.Request

	req, err = http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		err = fmt.Errorf("building download request: %w", err)

		return err
	}

	if accountID != "" || licenseKey != "" {
		req.SetBasicAuth(accountID, licenseKey)
	}

	var resp *http.Response

	resp, err = s.client.Do(req)
	if err != nil {
		err = fmt.Errorf("downloading database: %w", err)

		return err
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		err = fmt.Errorf("downloading database: unexpected status %d", resp.StatusCode)

		return err
	}

	var db []byte

	db, err = extractMMDB(resp.Body)
	if err != nil {
		return err
	}

	err = s.LoadBytes(db)

	return err
}

// extractMMDB reads a gzip-compressed tar stream and returns the bytes of the
// first .mmdb entry it finds. The MaxMind archive nests the database under a
// dated directory (e.g. GeoLite2-City_20260606/GeoLite2-City.mmdb).
func extractMMDB(r io.Reader) (db []byte, err error) {
	var gz *gzip.Reader

	gz, err = gzip.NewReader(r)
	if err != nil {
		err = fmt.Errorf("opening gzip stream: %w", err)

		return db, err
	}
	defer func() { _ = gz.Close() }()

	tr := tar.NewReader(gz)

	for {
		var header *tar.Header

		header, err = tr.Next()
		if errors.Is(err, io.EOF) {
			err = ErrNoMMDBInArchive

			return db, err
		}

		if err != nil {
			err = fmt.Errorf("reading tar stream: %w", err)

			return db, err
		}

		if header.Typeflag != tar.TypeReg || !strings.HasSuffix(header.Name, ".mmdb") {
			continue
		}

		db, err = io.ReadAll(io.LimitReader(tr, maxDBBytes))
		if err != nil {
			err = fmt.Errorf("reading mmdb from tar: %w", err)

			return db, err
		}

		return db, err
	}
}
