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

package cmd

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"syscall"

	"github.com/spf13/cobra"

	"github.com/nikogura/geoip-authz/pkg/authz"
	"github.com/nikogura/geoip-authz/pkg/config"
)

// serverCmd runs the ext_authz HTTP service.
//
//nolint:gochecknoglobals // Cobra boilerplate
var serverCmd = &cobra.Command{
	Use:          "server",
	Short:        "Run the geoip-authz ext_authz HTTP service",
	SilenceUsage: true,
	RunE: func(cmd *cobra.Command, _ []string) (err error) {
		err = runServer(cmd.Context())

		return err
	},
}

// runServer loads configuration and runs the service until interrupted.
func runServer(parent context.Context) (err error) {
	ctx, stop := signal.NotifyContext(parent, syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	log := slog.New(slog.NewJSONHandler(os.Stdout, nil))

	var cfg config.Config

	cfg, err = config.Load()
	if err != nil {
		err = fmt.Errorf("loading config: %w", err)

		return err
	}

	svc := authz.NewService(cfg, log)

	err = svc.Run(ctx)

	return err
}

//nolint:gochecknoinits // Cobra boilerplate
func init() {
	rootCmd.AddCommand(serverCmd)
}
