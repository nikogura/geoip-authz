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

package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"math/rand/v2"
	"net/http"
	"sync/atomic"
	"time"

	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/nikogura/geoip-authz/pkg/geoip"
	"github.com/nikogura/geoip-authz/pkg/metrics"
)

const (
	readHeaderTimeout = 10 * time.Second
	shutdownTimeout   = 10 * time.Second
	refreshRetryDelay = 5 * time.Minute
	jitterFraction    = 10
)

// Service is the geoip-authz runtime: it owns the geo database store and the
// blocklist policy, and serves the ext_authz HTTP surface.
type Service struct {
	cfg       config.Config
	store     *geoip.Store
	blocklist *geoip.Blocklist
	metrics   *metrics.Metrics
	log       *slog.Logger

	// mode is the hot-reloadable enforce/detect setting, read on every check via
	// the getter passed to the Handler so a reload takes effect without a
	// restart. Held behind an atomic pointer for lock-free reads.
	mode atomic.Pointer[config.Mode]

	// runtimeFingerprint is the signature of the hot-reloadable policy (mode,
	// fail-closed, blocklist) currently applied, used to skip redundant swaps
	// when a reload sees no change. Only touched by the single reload goroutine
	// (and once at startup before it runs).
	runtimeFingerprint string
}

// NewService builds a Service from resolved configuration.
func NewService(cfg config.Config, log *slog.Logger) (svc *Service) {
	if log == nil {
		log = slog.Default()
	}

	httpClient := &http.Client{Timeout: cfg.HTTPTimeout}

	svc = &Service{
		cfg:       cfg,
		store:     geoip.NewStore(httpClient),
		blocklist: geoip.NewBlocklist(cfg.BlockedCountries, cfg.BlockedRegions, cfg.FailClosed),
		log:       log,
	}

	// Seed the atomic mode and the runtime fingerprint from the boot config so
	// the first reload tick is a no-op when the file is unchanged.
	mode := cfg.Mode
	svc.mode.Store(&mode)
	svc.runtimeFingerprint = config.Runtime{
		Mode:       cfg.Mode,
		FailClosed: cfg.FailClosed,
		Countries:  cfg.BlockedCountries,
		Regions:    cfg.BlockedRegions,
	}.Fingerprint()

	return svc
}

// currentMode returns the live mode, read lock-free. Passed to the Handler so a
// hot-reload that flips mode takes effect on the next request.
func (s *Service) currentMode() (mode config.Mode) {
	mode = *s.mode.Load()

	return mode
}

// Run primes the database, starts the refresh loop, and serves until the
// context is cancelled.
func (s *Service) Run(ctx context.Context) (err error) {
	s.log.InfoContext(ctx, "starting geoip-authz",
		"mode", string(s.cfg.Mode),
		"listen", s.cfg.ListenAddr,
		"refresh_every", s.cfg.RefreshEvery.String(),
		"blocked_countries", len(s.cfg.BlockedCountries),
		"blocked_regions", len(s.cfg.BlockedRegions),
		"config_file", s.cfg.ConfigFile,
		"reload_every", s.cfg.ReloadEvery.String(),
		"fail_closed", s.cfg.FailClosed,
	)

	var metricsHandler http.Handler

	s.metrics, metricsHandler, err = metrics.New()
	if err != nil {
		err = fmt.Errorf("setting up metrics: %w", err)

		return err
	}

	err = s.metrics.RegisterDBLoaded(s.store.Ready)
	if err != nil {
		return err
	}

	err = s.metrics.RegisterBlocklistSize(s.blocklist.Sizes)
	if err != nil {
		return err
	}

	s.primeRuntime(ctx)

	s.primeDatabase(ctx)

	go s.refreshLoop(ctx)

	handler := NewHandler(s.blocklist, s.store, s.store.Ready, s.currentMode, s.cfg.ClientIPHeader, s.metrics, s.log)

	mux := handler.Routes()
	mux.Handle("/metrics", metricsHandler)

	err = s.serve(ctx, mux)

	return err
}

// primeDatabase performs the initial load. A failure is logged but not fatal:
// the refresh loop retries, and readiness stays false (so the replica receives
// no traffic and the edge fails closed) until a database is in place.
func (s *Service) primeDatabase(ctx context.Context) {
	err := s.loadOnce(ctx)
	s.metrics.ObserveRefresh(ctx, err == nil)

	if err != nil {
		s.log.ErrorContext(ctx, "initial database load failed; will retry", "error", err.Error())

		return
	}

	s.log.InfoContext(ctx, "geoip database loaded")
}

// primeRuntime starts the hot-reload loop that re-reads the config file for the
// hot-reloadable subset (mode, fail-closed, blocklist) — but only when a config
// file path is configured. The boot config already seeded the live policy in
// NewService, so there is no initial reload here; the loop simply watches for
// subsequent edits.
func (s *Service) primeRuntime(ctx context.Context) {
	if s.cfg.ConfigFile == "" {
		return
	}

	go s.runtimeReloadLoop(ctx)
}

// reloadRuntime re-reads the hot-reloadable subset from the config file and,
// when it differs from what is currently applied, atomically swaps in the new
// mode, fail-closed setting, and blocklist. It returns whether the policy
// actually changed (so an unchanged ConfigMap projection doesn't churn the live
// policy or spam events). An invalid file (e.g. a bad mode) returns an error and
// leaves the last-good policy untouched — the gate never goes down on a typo.
func (s *Service) reloadRuntime() (changed bool, err error) {
	var rt config.Runtime

	rt, err = config.LoadRuntime(s.cfg.ConfigFile)
	if err != nil {
		return changed, err
	}

	fingerprint := rt.Fingerprint()
	if fingerprint == s.runtimeFingerprint {
		return changed, err
	}

	mode := rt.Mode
	s.mode.Store(&mode)
	s.blocklist.Replace(rt.Countries, rt.Regions, rt.FailClosed)
	s.runtimeFingerprint = fingerprint
	changed = true

	return changed, err
}

// runtimeReloadLoop periodically re-reads the config file so an edit to mode,
// fail-closed, or the blocklist takes effect without a pod restart. A read or
// validation error is logged and the last-good policy retained (self-healing).
func (s *Service) runtimeReloadLoop(ctx context.Context) {
	ticker := time.NewTicker(s.cfg.ReloadEvery)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			changed, err := s.reloadRuntime()
			s.metrics.ObserveReload(ctx, err == nil)

			if err != nil {
				s.log.ErrorContext(ctx, "config reload failed; retaining last-good", "error", err.Error())

				continue
			}

			if changed {
				countries, regions := s.blocklist.Sizes()
				s.log.InfoContext(ctx, "config hot-reloaded",
					"mode", string(s.currentMode()), "countries", countries, "regions", regions)
			}
		}
	}
}

// loadOnce loads from a local file when DBPath is set, otherwise fetches the
// database from the configured URL.
func (s *Service) loadOnce(ctx context.Context) (err error) {
	if s.cfg.DBPath != "" {
		err = s.store.LoadFile(s.cfg.DBPath)

		return err
	}

	err = s.store.Fetch(ctx, s.cfg.DownloadURL, s.cfg.AccountID, s.cfg.LicenseKey)

	return err
}

// refreshLoop periodically reloads the database. The first tick is jittered so
// replicas do not pull from the source in lockstep; failed refreshes retry
// sooner than the full interval and retain the last-good database.
func (s *Service) refreshLoop(ctx context.Context) {
	if s.cfg.DBPath != "" {
		return // static local database; nothing to refresh
	}

	timer := time.NewTimer(jitter(s.cfg.RefreshEvery))
	defer timer.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-timer.C:
			err := s.store.Fetch(ctx, s.cfg.DownloadURL, s.cfg.AccountID, s.cfg.LicenseKey)
			s.metrics.ObserveRefresh(ctx, err == nil)

			if err != nil {
				s.log.ErrorContext(ctx, "database refresh failed; retaining last-good", "error", err.Error())
				timer.Reset(refreshRetryDelay)

				continue
			}

			s.log.InfoContext(ctx, "geoip database refreshed")
			timer.Reset(s.cfg.RefreshEvery)
		}
	}
}

// serve runs the HTTP server and shuts it down gracefully on context cancel.
func (s *Service) serve(ctx context.Context, handler http.Handler) (err error) {
	httpServer := &http.Server{
		Addr:              s.cfg.ListenAddr,
		Handler:           handler,
		ReadHeaderTimeout: readHeaderTimeout,
	}

	errCh := make(chan error, 1)

	go func() {
		serveErr := httpServer.ListenAndServe()
		if serveErr != nil && !errors.Is(serveErr, http.ErrServerClosed) {
			errCh <- serveErr

			return
		}

		errCh <- nil
	}()

	select {
	case <-ctx.Done():
		s.log.InfoContext(ctx, "shutting down")

		shutdownCtx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
		defer cancel()

		err = httpServer.Shutdown(shutdownCtx)
		if err != nil {
			err = fmt.Errorf("graceful shutdown: %w", err)

			return err
		}

		return err
	case err = <-errCh:
		if err != nil {
			err = fmt.Errorf("http server: %w", err)

			return err
		}

		return err
	}
}

// jitter returns d reduced by a random fraction of up to 10%, spreading replica
// refreshes. The randomness is non-cryptographic on purpose.
func jitter(d time.Duration) (out time.Duration) {
	out = d

	span := int64(d) / jitterFraction
	if span <= 0 {
		return out
	}

	out = d - time.Duration(rand.Int64N(span)) //nolint:gosec // jitter is not security-sensitive

	return out
}
