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

// Package tracing configures OpenTelemetry distributed tracing. Tracing is
// enabled only when an OTLP endpoint is configured via the standard
// OTEL_EXPORTER_OTLP_ENDPOINT (or _TRACES_ENDPOINT) environment variables;
// otherwise a no-op provider is installed so the service behaves identically
// with or without a collector.
package tracing

import (
	"context"
	"fmt"
	"os"

	"go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlptrace/otlptracehttp"
	"go.opentelemetry.io/otel/propagation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	tracenoop "go.opentelemetry.io/otel/trace/noop"
)

// Init installs the global tracer provider and propagator. It returns a
// shutdown function the caller must invoke on exit to flush spans.
func Init(ctx context.Context, serviceName, version string) (shutdown func(ctx context.Context) (err error), err error) {
	shutdown = func(_ context.Context) (sErr error) { return sErr }

	if os.Getenv("OTEL_EXPORTER_OTLP_ENDPOINT") == "" && os.Getenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT") == "" {
		otel.SetTracerProvider(tracenoop.NewTracerProvider())

		return shutdown, err
	}

	exporter, expErr := otlptracehttp.New(ctx)
	if expErr != nil {
		err = fmt.Errorf("creating otlp trace exporter: %w", expErr)

		return shutdown, err
	}

	res := resource.NewSchemaless(
		attribute.String("service.name", serviceName),
		attribute.String("service.version", version),
	)

	provider := sdktrace.NewTracerProvider(
		sdktrace.WithBatcher(exporter),
		sdktrace.WithResource(res),
	)

	otel.SetTracerProvider(provider)
	otel.SetTextMapPropagator(propagation.NewCompositeTextMapPropagator(
		propagation.TraceContext{},
		propagation.Baggage{},
	))

	shutdown = provider.Shutdown

	return shutdown, err
}
