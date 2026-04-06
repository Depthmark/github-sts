// Command benchviz reads benchmark JSON output and generates SVG charts
// for embedding in GitHub documentation.
//
// Usage:
//
//	go run ./cmd/benchviz -input bench-results.json -outdir docs/benchmarks
//
// Generates:
//   - scaling.svg     — throughput scaling by number of GitHub Apps
//   - latency.svg     — p50/p95/p99 latency under realistic conditions
//   - projection.svg  — apps needed for target throughput
//   - summary.svg     — combined dashboard with key metrics
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strings"
)

// Matches the JSON structure from bench_test.go.
type BenchmarkReport struct {
	Timestamp        string             `json:"timestamp"`
	GoVersion        string             `json:"go_version"`
	RateLimitPerApp  int                `json:"rate_limit_per_app_per_hour"`
	SimulatedLatency string             `json:"simulated_github_api_latency"`
	Scenarios        []ScenarioResult   `json:"scenarios"`
	Scaling          []ScalingResult    `json:"scaling"`
	Projection       []ProjectionResult `json:"projection"`
	Internal         InternalCeiling    `json:"internal_ceiling"`
}

type ScenarioResult struct {
	Name        string  `json:"name"`
	Apps        int     `json:"apps"`
	Requests    int64   `json:"requests"`
	Successes   int64   `json:"successes"`
	Errors      int64   `json:"errors"`
	RateLimited int64   `json:"rate_limited"`
	ReqPerMin   float64 `json:"req_per_min"`
	ReqPerHour  float64 `json:"req_per_hour"`
	SuccessRate float64 `json:"success_rate_pct"`
	LatencyP50  float64 `json:"latency_p50_ms"`
	LatencyP95  float64 `json:"latency_p95_ms"`
	LatencyP99  float64 `json:"latency_p99_ms"`
	LatencyMax  float64 `json:"latency_max_ms"`
	Concurrency int     `json:"concurrency"`
	DurationSec float64 `json:"duration_sec"`
}

type ScalingResult struct {
	Apps            int     `json:"apps"`
	TheoreticalMax  float64 `json:"theoretical_max_per_hour"`
	MeasuredPerMin  float64 `json:"measured_per_min"`
	MeasuredPerHour float64 `json:"measured_per_hour"`
	Efficiency      float64 `json:"efficiency_pct"`
	SuccessRate     float64 `json:"success_rate_pct"`
	LatencyP99      float64 `json:"latency_p99_ms"`
}

type ProjectionResult struct {
	TargetPerHour   int     `json:"target_per_hour"`
	AppsNeeded      int     `json:"apps_needed"`
	EffectivePerMin float64 `json:"effective_per_min"`
}

type InternalCeiling struct {
	ReqPerMin  float64 `json:"req_per_min_no_ratelimit"`
	LatencyP50 float64 `json:"latency_p50_ms"`
	LatencyP99 float64 `json:"latency_p99_ms"`
	Note       string  `json:"note"`
}

func main() {
	input := flag.String("input", "bench-results.json", "Path to benchmark JSON")
	outdir := flag.String("outdir", "docs/benchmarks", "Output directory for SVGs")
	flag.Parse()

	data, err := os.ReadFile(*input)
	if err != nil {
		fmt.Fprintf(os.Stderr, "reading %s: %v\n", *input, err)
		os.Exit(1)
	}

	var report BenchmarkReport
	if err := json.Unmarshal(data, &report); err != nil {
		fmt.Fprintf(os.Stderr, "parsing JSON: %v\n", err)
		os.Exit(1)
	}

	if err := os.MkdirAll(*outdir, 0755); err != nil {
		fmt.Fprintf(os.Stderr, "creating output dir: %v\n", err)
		os.Exit(1)
	}

	charts := []struct {
		name string
		fn   func(BenchmarkReport) string
	}{
		{"scaling.svg", genScalingChart},
		{"latency.svg", genLatencyChart},
		{"projection.svg", genProjectionChart},
		{"summary.svg", genSummaryChart},
	}

	for _, c := range charts {
		path := filepath.Join(*outdir, c.name)
		svg := c.fn(report)
		if err := os.WriteFile(path, []byte(svg), 0644); err != nil {
			fmt.Fprintf(os.Stderr, "writing %s: %v\n", path, err)
			os.Exit(1)
		}
		fmt.Printf("Generated %s\n", path)
	}
}

// ---------------------------------------------------------------------------
// Scaling chart: measured throughput vs theoretical max by # of apps
// ---------------------------------------------------------------------------

func genScalingChart(r BenchmarkReport) string {
	const (
		w         = 720
		h         = 400
		padLeft   = 100
		padRight  = 30
		padTop    = 55
		padBottom = 80
	)

	chartW := float64(w - padLeft - padRight)
	chartH := float64(h - padTop - padBottom)

	maxVal := float64(0)
	for _, s := range r.Scaling {
		if s.TheoreticalMax > maxVal {
			maxVal = s.TheoreticalMax
		}
	}
	maxVal = ceilNice(maxVal)

	n := len(r.Scaling)
	if n == 0 {
		return `<svg xmlns="http://www.w3.org/2000/svg" width="720" height="400"><text x="360" y="200" text-anchor="middle">No scaling data</text></svg>`
	}
	groupW := chartW / float64(n)
	barW := groupW * 0.35

	var bars strings.Builder

	// Y-axis grid.
	for i := 0; i <= 4; i++ {
		val := maxVal * float64(i) / 4
		y := float64(padTop) + chartH - (chartH * float64(i) / 4)
		bars.WriteString(fmt.Sprintf(
			`<line x1="%d" y1="%.0f" x2="%.0f" y2="%.0f" stroke="#e0e0e0" stroke-width="1"/>`,
			padLeft, y, float64(w-padRight), y))
		bars.WriteString(fmt.Sprintf(
			`<text x="%d" y="%.0f" text-anchor="end" font-size="11" fill="#666" font-family="system-ui, sans-serif">%s</text>`,
			padLeft-8, y+4, fmtK(val)))
	}

	for i, s := range r.Scaling {
		groupX := float64(padLeft) + float64(i)*groupW

		// Theoretical bar (gray, behind).
		theoH := chartH * s.TheoreticalMax / maxVal
		theoY := float64(padTop) + chartH - theoH
		bars.WriteString(fmt.Sprintf(
			`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3" fill="#e0e0e0"/>`,
			groupX+groupW*0.1, theoY, barW, theoH))

		// Measured bar (blue, front).
		measH := chartH * s.MeasuredPerHour / maxVal
		measY := float64(padTop) + chartH - measH
		bars.WriteString(fmt.Sprintf(
			`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3" fill="#1976D2"/>`,
			groupX+groupW*0.1+barW+4, measY, barW, measH))

		// Value label.
		bars.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%.1f" text-anchor="middle" font-size="11" font-weight="bold" fill="#1976D2" font-family="system-ui, sans-serif">%s</text>`,
			groupX+groupW/2, measY-6, fmtK(s.MeasuredPerHour)))

		// X-axis label.
		bars.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%d" text-anchor="middle" font-size="12" fill="#333" font-family="system-ui, sans-serif">%d apps</text>`,
			groupX+groupW/2, h-padBottom+20, s.Apps))

		// Efficiency label.
		bars.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%d" text-anchor="middle" font-size="10" fill="#999" font-family="system-ui, sans-serif">%.0f%% eff</text>`,
			groupX+groupW/2, h-padBottom+35, s.Efficiency))
	}

	// Legend.
	bars.WriteString(fmt.Sprintf(
		`<rect x="%d" y="12" width="12" height="12" rx="2" fill="#e0e0e0"/><text x="%d" y="23" font-size="11" fill="#666" font-family="system-ui, sans-serif">Theoretical max</text>`,
		w-230, w-214))
	bars.WriteString(fmt.Sprintf(
		`<rect x="%d" y="12" width="12" height="12" rx="2" fill="#1976D2"/><text x="%d" y="23" font-size="11" fill="#666" font-family="system-ui, sans-serif">Measured</text>`,
		w-110, w-94))

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">
<rect width="%d" height="%d" fill="#fafafa" rx="8"/>
<text x="%d" y="30" font-size="16" font-weight="bold" fill="#222" font-family="system-ui, sans-serif">Throughput Scaling (tokens/hour) — %dK rate limit/app</text>
%s
<text x="%d" y="%d" text-anchor="middle" font-size="12" fill="#666" font-family="system-ui, sans-serif">Number of GitHub Apps</text>
</svg>`, w, h, w, h, w, h, padLeft, r.RateLimitPerApp/1000, bars.String(), w/2, h-8)
}

// ---------------------------------------------------------------------------
// Latency chart: p50/p95/p99 for rate-limited scenarios
// ---------------------------------------------------------------------------

func genLatencyChart(r BenchmarkReport) string {
	const (
		w         = 720
		h         = 400
		padLeft   = 80
		padRight  = 140
		padTop    = 55
		padBottom = 80
	)

	// Filter to rate-limited scenarios (the N-apps ones).
	var scenarios []ScenarioResult
	for _, s := range r.Scenarios {
		if s.Apps > 0 && strings.Contains(s.Name, "apps") {
			scenarios = append(scenarios, s)
		}
	}

	if len(scenarios) == 0 {
		return `<svg xmlns="http://www.w3.org/2000/svg" width="720" height="400"><text x="360" y="200" text-anchor="middle">No latency data</text></svg>`
	}

	chartW := float64(w - padLeft - padRight)
	chartH := float64(h - padTop - padBottom)

	maxVal := float64(0)
	for _, s := range scenarios {
		if s.LatencyP99 > maxVal {
			maxVal = s.LatencyP99
		}
	}
	maxVal = ceilNice(maxVal)

	n := len(scenarios)
	groupW := chartW / float64(n)
	subBarW := groupW * 0.25
	colors := []string{"#4CAF50", "#FFA726", "#EF5350"}
	labels := []string{"p50", "p95", "p99"}

	var bars strings.Builder

	// Y-axis grid.
	for i := 0; i <= 4; i++ {
		val := maxVal * float64(i) / 4
		y := float64(padTop) + chartH - (chartH * float64(i) / 4)
		bars.WriteString(fmt.Sprintf(
			`<line x1="%d" y1="%.0f" x2="%.0f" y2="%.0f" stroke="#e0e0e0" stroke-width="1"/>`,
			padLeft, y, float64(w-padRight), y))
		bars.WriteString(fmt.Sprintf(
			`<text x="%d" y="%.0f" text-anchor="end" font-size="11" fill="#666" font-family="system-ui, sans-serif">%.0fms</text>`,
			padLeft-8, y+4, val))
	}

	for i, s := range scenarios {
		vals := []float64{s.LatencyP50, s.LatencyP95, s.LatencyP99}
		groupX := float64(padLeft) + float64(i)*groupW

		for j, v := range vals {
			x := groupX + float64(j)*subBarW + groupW*0.1
			barH := chartH * v / maxVal
			y := float64(padTop) + chartH - barH
			bars.WriteString(fmt.Sprintf(
				`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="2" fill="%s"/>`,
				x, y, subBarW-2, barH, colors[j]))
		}

		bars.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%d" text-anchor="middle" font-size="12" fill="#333" font-family="system-ui, sans-serif">%d apps</text>`,
			groupX+groupW/2, h-padBottom+20, s.Apps))
	}

	// Legend.
	legendX := w - padRight + 15
	for i, label := range labels {
		y := padTop + 20 + i*25
		bars.WriteString(fmt.Sprintf(
			`<rect x="%d" y="%d" width="14" height="14" rx="2" fill="%s"/>`,
			legendX, y-11, colors[i]))
		bars.WriteString(fmt.Sprintf(
			`<text x="%d" y="%d" font-size="12" fill="#666" font-family="system-ui, sans-serif">%s</text>`,
			legendX+20, y, label))
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">
<rect width="%d" height="%d" fill="#fafafa" rx="8"/>
<text x="%d" y="30" font-size="16" font-weight="bold" fill="#222" font-family="system-ui, sans-serif">Latency Percentiles (ms) — with simulated GitHub API latency</text>
%s
<text x="%d" y="%d" text-anchor="middle" font-size="12" fill="#666" font-family="system-ui, sans-serif">Number of GitHub Apps (rate limited at %dK/hr each)</text>
</svg>`, w, h, w, h, w, h, padLeft, bars.String(), (padLeft+w-padRight)/2, h-8, r.RateLimitPerApp/1000)
}

// ---------------------------------------------------------------------------
// Projection chart: apps needed for target throughput
// ---------------------------------------------------------------------------

func genProjectionChart(r BenchmarkReport) string {
	const (
		w         = 720
		h         = 350
		padLeft   = 100
		padRight  = 60
		padTop    = 55
		padBottom = 70
	)

	if len(r.Projection) == 0 {
		return `<svg xmlns="http://www.w3.org/2000/svg" width="720" height="350"><text x="360" y="175" text-anchor="middle">No projection data</text></svg>`
	}

	chartW := float64(w - padLeft - padRight)
	chartH := float64(h - padTop - padBottom)

	maxApps := 0
	for _, p := range r.Projection {
		if p.AppsNeeded > maxApps {
			maxApps = p.AppsNeeded
		}
	}
	maxAppsF := ceilNice(float64(maxApps))

	n := len(r.Projection)
	barW := chartW / float64(n) * 0.6
	gap := chartW / float64(n) * 0.4

	var bars strings.Builder

	// Y-axis grid.
	for i := 0; i <= 4; i++ {
		val := maxAppsF * float64(i) / 4
		y := float64(padTop) + chartH - (chartH * float64(i) / 4)
		bars.WriteString(fmt.Sprintf(
			`<line x1="%d" y1="%.0f" x2="%.0f" y2="%.0f" stroke="#e0e0e0" stroke-width="1"/>`,
			padLeft, y, float64(w-padRight), y))
		bars.WriteString(fmt.Sprintf(
			`<text x="%d" y="%.0f" text-anchor="end" font-size="11" fill="#666" font-family="system-ui, sans-serif">%.0f</text>`,
			padLeft-8, y+4, val))
	}

	// Y-axis label.
	bars.WriteString(fmt.Sprintf(
		`<text x="15" y="%d" font-size="12" fill="#666" font-family="system-ui, sans-serif" transform="rotate(-90, 15, %d)">GitHub Apps needed</text>`,
		(padTop+h-padBottom)/2, (padTop+h-padBottom)/2))

	for i, p := range r.Projection {
		x := float64(padLeft) + float64(i)*(barW+gap) + gap/2
		barH := chartH * float64(p.AppsNeeded) / maxAppsF
		y := float64(padTop) + chartH - barH

		color := "#FF9800"
		if p.TargetPerHour >= 100000 {
			color = "#EF5350"
		} else if p.TargetPerHour <= 50000 {
			color = "#4CAF50"
		}

		bars.WriteString(fmt.Sprintf(
			`<rect x="%.1f" y="%.1f" width="%.1f" height="%.1f" rx="3" fill="%s"/>`,
			x, y, barW, barH, color))
		bars.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%.1f" text-anchor="middle" font-size="13" font-weight="bold" fill="#333" font-family="system-ui, sans-serif">%d</text>`,
			x+barW/2, y-8, p.AppsNeeded))
		bars.WriteString(fmt.Sprintf(
			`<text x="%.1f" y="%d" text-anchor="middle" font-size="11" fill="#333" font-family="system-ui, sans-serif">%sK/hr</text>`,
			x+barW/2, h-padBottom+18, fmtK(float64(p.TargetPerHour)/1000)))
	}

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">
<rect width="%d" height="%d" fill="#fafafa" rx="8"/>
<text x="%d" y="30" font-size="16" font-weight="bold" fill="#222" font-family="system-ui, sans-serif">Capacity Projection — Apps Needed by Target Throughput</text>
%s
<text x="%d" y="%d" text-anchor="middle" font-size="12" fill="#666" font-family="system-ui, sans-serif">Target (tokens/hour)</text>
</svg>`, w, h, w, h, w, h, padLeft, bars.String(), w/2, h-8)
}

// ---------------------------------------------------------------------------
// Summary dashboard
// ---------------------------------------------------------------------------

func genSummaryChart(r BenchmarkReport) string {
	const (
		w = 720
		h = 340
	)

	// Find peak measured scenario.
	var peakHour float64
	var peakApps int
	var peakP99 float64
	var peakSuccess float64
	for _, s := range r.Scaling {
		if s.MeasuredPerHour > peakHour {
			peakHour = s.MeasuredPerHour
			peakApps = s.Apps
			peakP99 = s.LatencyP99
			peakSuccess = s.SuccessRate
		}
	}

	// Find apps needed for 100K.
	apps100k := 0
	for _, p := range r.Projection {
		if p.TargetPerHour == 100_000 {
			apps100k = p.AppsNeeded
		}
	}

	cards := []struct {
		label string
		value string
		sub   string
		color string
	}{
		{"Peak Measured", fmtK(peakHour) + "/hr", fmt.Sprintf("%d apps, rate limited", peakApps), "#1976D2"},
		{"p99 Latency", fmt.Sprintf("%.0fms", peakP99), "with simulated API latency", "#EF5350"},
		{"Success Rate", fmt.Sprintf("%.0f%%", peakSuccess), "under rate limits", "#4CAF50"},
		{"100K/hr Needs", fmt.Sprintf("%d apps", apps100k), fmt.Sprintf("%dK limit/app/hr", r.RateLimitPerApp/1000), "#FF9800"},
	}

	var svg strings.Builder

	cardW := (w - 40) / len(cards)
	for i, c := range cards {
		x := 20 + i*cardW
		cw := cardW - 10
		svg.WriteString(fmt.Sprintf(
			`<rect x="%d" y="60" width="%d" height="190" rx="8" fill="white" stroke="#e0e0e0"/>`,
			x, cw))
		svg.WriteString(fmt.Sprintf(
			`<rect x="%d" y="60" width="%d" height="6" rx="3" fill="%s"/>`,
			x, cw, c.color))
		svg.WriteString(fmt.Sprintf(
			`<text x="%d" y="100" text-anchor="middle" font-size="12" fill="#666" font-family="system-ui, sans-serif">%s</text>`,
			x+cw/2, c.label))
		svg.WriteString(fmt.Sprintf(
			`<text x="%d" y="160" text-anchor="middle" font-size="28" font-weight="bold" fill="#222" font-family="system-ui, sans-serif">%s</text>`,
			x+cw/2, c.value))
		svg.WriteString(fmt.Sprintf(
			`<text x="%d" y="190" text-anchor="middle" font-size="11" fill="#999" font-family="system-ui, sans-serif">%s</text>`,
			x+cw/2, c.sub))
	}

	subtitle := fmt.Sprintf("Internal ceiling: %s req/min · GitHub API latency: %s",
		fmtK(r.Internal.ReqPerMin), r.SimulatedLatency)

	return fmt.Sprintf(`<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %d %d" width="%d" height="%d">
<rect width="%d" height="%d" fill="#fafafa" rx="8"/>
<text x="20" y="30" font-size="16" font-weight="bold" fill="#222" font-family="system-ui, sans-serif">github-sts Realistic Performance</text>
<text x="%d" y="30" text-anchor="end" font-size="11" fill="#999" font-family="system-ui, sans-serif">%s</text>
<text x="20" y="48" font-size="11" fill="#999" font-family="system-ui, sans-serif">%s</text>
%s
<text x="%d" y="%d" text-anchor="middle" font-size="10" fill="#bbb" font-family="system-ui, sans-serif">Benchmarked with simulated GitHub API latency (%s) and rate limits (%dK/hr per app)</text>
</svg>`, w, h, w, h, w, h, w-20, r.Timestamp, subtitle, svg.String(), w/2, h-10, r.SimulatedLatency, r.RateLimitPerApp/1000)
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func fmtK(v float64) string {
	if v >= 1_000_000 {
		return fmt.Sprintf("%.0fM", v/1_000_000)
	}
	if v >= 1000 {
		return fmt.Sprintf("%.0fK", v/1000)
	}
	return fmt.Sprintf("%.0f", v)
}

func ceilNice(v float64) float64 {
	if v <= 0 {
		return 100
	}
	mag := math.Pow(10, math.Floor(math.Log10(v)))
	normalized := v / mag
	switch {
	case normalized <= 1:
		return mag
	case normalized <= 2:
		return 2 * mag
	case normalized <= 5:
		return 5 * mag
	default:
		return 10 * mag
	}
}
