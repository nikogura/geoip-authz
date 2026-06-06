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

// White-box tests for unexported runtime helpers.
package authz

import (
	"context"
	"testing"
	"time"

	"github.com/nikogura/geoip-authz/pkg/config"
	"github.com/stretchr/testify/require"
)

func TestJitter_WithinBounds(t *testing.T) {
	t.Parallel()

	const base = 24 * time.Hour
	for range 100 {
		out := jitter(base)
		require.LessOrEqual(t, out, base)
		require.GreaterOrEqual(t, out, base-base/jitterFraction)
	}
}

func TestJitter_NonPositive(t *testing.T) {
	t.Parallel()

	require.Equal(t, time.Duration(0), jitter(0))
}

// TestRun_GracefulShutdown verifies the service starts (even when the initial
// database load fails — non-fatal) and returns cleanly when the context is
// cancelled.
func TestRun_GracefulShutdown(t *testing.T) {
	t.Parallel()

	cfg := config.Config{
		ListenAddr:   "127.0.0.1:0", // ephemeral port
		Mode:         config.ModeDetect,
		DownloadURL:  "http://127.0.0.1:0/never", // prime fails fast, non-fatal
		RefreshEvery: time.Hour,
		HTTPTimeout:  time.Second,
		FailClosed:   true,
	}

	svc := NewService(cfg, nil)

	ctx, cancel := context.WithCancel(context.Background())

	done := make(chan error, 1)
	go func() {
		done <- svc.Run(ctx)
	}()

	// Give the server a moment to come up, then signal shutdown.
	time.Sleep(50 * time.Millisecond)
	cancel()

	select {
	case err := <-done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("Run did not return after context cancellation")
	}
}
