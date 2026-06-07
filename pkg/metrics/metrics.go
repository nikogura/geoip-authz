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

// Package metrics is the instrumentation layer. It builds an OpenTelemetry
// meter wired to a Prometheus exporter and exposes the golden signals — traffic,
// errors, latency, saturation — plus database health, for scraping at /metrics.
package metrics

import (
	"context"
	"fmt"
	"net/http"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"go.opentelemetry.io/otel/attribute"
	otelprom "go.opentelemetry.io/otel/exporters/prometheus"
	"go.opentelemetry.io/otel/metric"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
)

const meterName = "github.com/nikogura/geoip-authz"

// durationName is the latency instrument name; the explicit-bucket View keys off it.
const durationName = "geoip.authz.check.duration"

// durationBucketsSeconds are explicit histogram boundaries (in SECONDS) sized for
// this operation. A geo lookup is tens of microseconds, so the OTel default
// boundaries ([5, 10, 25, … 10000]) — which are calibrated for milliseconds — put
// every observation in the first bucket and make histogram_quantile interpolate a
// bogus multi-second p95 (0.95 × 5s = 4.75s). These boundaries resolve from ~25µs
// up to 5s so the quantiles reflect reality.
//
//nolint:gochecknoglobals // shared bucket boundaries for the duration View
var durationBucketsSeconds = []float64{
	0.000025, 0.00005, 0.0001, 0.00025, 0.0005, 0.001, 0.0025, 0.005,
	0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5,
}

// Metrics holds the OpenTelemetry instruments for the golden signals. A nil
// *Metrics is safe to use — every method is a no-op — so callers needn't guard.
type Metrics struct {
	meter    metric.Meter
	checks   metric.Int64Counter       // traffic + errors (by verdict/reason)
	duration metric.Float64Histogram   // latency
	inflight metric.Int64UpDownCounter // saturation
	refresh  metric.Int64Counter       // database refresh outcomes
	reload   metric.Int64Counter       // blocklist hot-reload outcomes
}

// New builds a Metrics backed by an OTel MeterProvider with a Prometheus
// exporter, and returns an http.Handler that serves the metrics in Prometheus
// text format. Each call uses its own registry, so it is safe to construct
// independently (e.g. in tests) without global-registry collisions.
func New() (m *Metrics, handler http.Handler, err error) {
	registry := prometheus.NewRegistry()

	var exporter *otelprom.Exporter

	exporter, err = otelprom.New(otelprom.WithRegisterer(registry))
	if err != nil {
		err = fmt.Errorf("creating prometheus exporter: %w", err)

		return m, handler, err
	}

	// Override the default histogram boundaries for the latency instrument; the
	// defaults are millisecond-scaled and wreck quantiles on a seconds-valued,
	// microsecond-fast metric (see durationBucketsSeconds).
	durationView := sdkmetric.NewView(
		sdkmetric.Instrument{Name: durationName},
		sdkmetric.Stream{Aggregation: sdkmetric.AggregationExplicitBucketHistogram{
			Boundaries: durationBucketsSeconds,
		}},
	)

	provider := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(exporter),
		sdkmetric.WithView(durationView),
	)
	meter := provider.Meter(meterName)

	m = &Metrics{meter: meter}

	m.checks, err = meter.Int64Counter(
		"geoip.authz.checks",
		metric.WithDescription("Total ext_authz checks served, by verdict/reason/denied."),
	)
	if err != nil {
		err = fmt.Errorf("creating checks counter: %w", err)

		return m, handler, err
	}

	m.duration, err = meter.Float64Histogram(
		durationName,
		metric.WithUnit("s"),
		metric.WithDescription("ext_authz check latency in seconds."),
	)
	if err != nil {
		err = fmt.Errorf("creating duration histogram: %w", err)

		return m, handler, err
	}

	m.inflight, err = meter.Int64UpDownCounter(
		"geoip.authz.inflight.requests",
		metric.WithDescription("In-flight ext_authz checks (saturation)."),
	)
	if err != nil {
		err = fmt.Errorf("creating inflight gauge: %w", err)

		return m, handler, err
	}

	m.refresh, err = meter.Int64Counter(
		"geoip.authz.db.refresh",
		metric.WithDescription("Database refresh attempts, by success."),
	)
	if err != nil {
		err = fmt.Errorf("creating refresh counter: %w", err)

		return m, handler, err
	}

	m.reload, err = meter.Int64Counter(
		"geoip.authz.blocklist.reload",
		metric.WithDescription("Blocklist hot-reload attempts, by success."),
	)
	if err != nil {
		err = fmt.Errorf("creating blocklist reload counter: %w", err)

		return m, handler, err
	}

	handler = promhttp.HandlerFor(registry, promhttp.HandlerOpts{})

	return m, handler, err
}

// RegisterDBLoaded registers an observable gauge reporting 1 when the database
// is loaded and 0 otherwise, sampled from ready at collection time.
func (m *Metrics) RegisterDBLoaded(ready func() (loaded bool)) (err error) {
	if m == nil {
		return err
	}

	_, err = m.meter.Int64ObservableGauge(
		"geoip.authz.db.loaded",
		metric.WithDescription("1 if the geo database is loaded, else 0."),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) (cbErr error) {
			var value int64
			if ready() {
				value = 1
			}

			observer.Observe(value)

			return cbErr
		}),
	)
	if err != nil {
		err = fmt.Errorf("registering db_loaded gauge: %w", err)

		return err
	}

	return err
}

// RegisterBlocklistSize registers an observable gauge reporting the number of
// blocked countries and regions currently loaded, sampled from sizes at
// collection time and labelled by scope ("country"/"region").
func (m *Metrics) RegisterBlocklistSize(sizes func() (countries, regions int)) (err error) {
	if m == nil {
		return err
	}

	_, err = m.meter.Int64ObservableGauge(
		"geoip.authz.blocklist.size",
		metric.WithDescription("Entries in the active blocklist, by scope."),
		metric.WithInt64Callback(func(_ context.Context, observer metric.Int64Observer) (cbErr error) {
			countries, regions := sizes()
			observer.Observe(int64(countries), metric.WithAttributes(attribute.String("scope", "country")))
			observer.Observe(int64(regions), metric.WithAttributes(attribute.String("scope", "region")))

			return cbErr
		}),
	)
	if err != nil {
		err = fmt.Errorf("registering blocklist_size gauge: %w", err)

		return err
	}

	return err
}

// ObserveReload records a blocklist hot-reload attempt and its outcome.
func (m *Metrics) ObserveReload(ctx context.Context, success bool) {
	if m == nil {
		return
	}

	m.reload.Add(ctx, 1, metric.WithAttributes(attribute.Bool("success", success)))
}

// ObserveCheck records one ext_authz check: the traffic/error counter (labelled
// by verdict, reason, and whether it was denied) and the latency histogram.
func (m *Metrics) ObserveCheck(ctx context.Context, verdict, reason string, denied bool, seconds float64) {
	if m == nil {
		return
	}

	m.checks.Add(ctx, 1, metric.WithAttributes(
		attribute.String("verdict", verdict),
		attribute.String("reason", reason),
		attribute.Bool("denied", denied),
	))
	m.duration.Record(ctx, seconds, metric.WithAttributes(attribute.String("verdict", verdict)))
}

// InflightAdd adjusts the in-flight request gauge (saturation): +1 on entry,
// -1 on exit.
func (m *Metrics) InflightAdd(ctx context.Context, delta int64) {
	if m == nil {
		return
	}

	m.inflight.Add(ctx, delta)
}

// ObserveRefresh records a database refresh attempt and its outcome.
func (m *Metrics) ObserveRefresh(ctx context.Context, success bool) {
	if m == nil {
		return
	}

	m.refresh.Add(ctx, 1, metric.WithAttributes(attribute.Bool("success", success)))
}
