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

// Package cmd wires the geoip-authz command-line surface.
package cmd

import (
	"os"

	"github.com/spf13/cobra"
)

// rootCmd is the geoip-authz entrypoint.
//
//nolint:gochecknoglobals // Cobra boilerplate
var rootCmd = &cobra.Command{
	Use:   "geoip-authz",
	Short: "GeoIP ext_authz service for reverse proxies",
	Long: `
geoip-authz answers reverse-proxy ext_authz checks. It loads a MaxMind
GeoLite2-City database, resolves the client IP to a country and subdivision,
and returns 403 for clients matching an operator-supplied blocklist. In detect
mode it annotates and logs the verdict without blocking.
`,
}

// Execute runs the root command, exiting non-zero on error.
func Execute() {
	err := rootCmd.Execute()
	if err != nil {
		os.Exit(1)
	}
}
