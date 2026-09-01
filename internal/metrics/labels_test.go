package metrics

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/prometheus/client_golang/prometheus"
)

// reservedLabels are injected by Kubernetes service discovery and by
// Prometheus Operator's ServiceMonitor. A metric exposing one of these does
// not produce an error: the scrape silently wins, and the application's
// value is renamed to exported_* or lost entirely. The failure is invisible
// until a dashboard returns no rows.
//
// This is not hypothetical in this project. A "GitHub App Instance"
// dashboard variable built on exported_instance was found to be permanently
// empty, because the label it selected on never existed: the scrape had
// taken `instance` and the app's own value did not survive.
var reservedLabels = map[string]string{
	"app":       "k8s workload label, and a Loki stream label",
	"instance":  "Prometheus scrape target (pod IP:port)",
	"job":       "Prometheus scrape job name",
	"endpoint":  "ServiceMonitor: scraped service port name",
	"service":   "ServiceMonitor: scraped service",
	"namespace": "k8s namespace",
	"pod":       "k8s pod name",
	"container": "k8s container name",
	"node":      "k8s node name",
}

var labelListPattern = regexp.MustCompile(`\[\]string\{([^}]*)\}`)

// TestNoReservedLabelNames reads the metric declarations straight from
// source. Every metric in this package declares its labels in one
// []string{...} literal, so this covers metrics added later without anyone
// remembering to update a list here.
//
// Source inspection rather than runtime gathering is deliberate:
// prometheus.Gather only reports a *Vec once it has at least one child, so a
// runtime walk would pass vacuously for any metric no test happens to
// increment -- exactly the new ones most likely to get this wrong.
func TestNoReservedLabelNames(t *testing.T) {
	source, err := os.ReadFile("metrics.go")
	if err != nil {
		t.Fatalf("read metrics.go: %v", err)
	}

	matches := labelListPattern.FindAllStringSubmatch(string(source), -1)
	if len(matches) == 0 {
		t.Fatal("found no []string{...} label declarations; the pattern is stale and this test is inert")
	}

	checked := 0
	for _, match := range matches {
		for _, raw := range strings.Split(match[1], ",") {
			label := strings.Trim(strings.TrimSpace(raw), `"`)
			if label == "" {
				continue
			}
			checked++
			if why, reserved := reservedLabels[label]; reserved {
				t.Errorf("reserved label %q declared in %s\n  reason: %s\n  fix: prefix it, e.g. github_%s",
					label, strings.TrimSpace(match[0]), why, label)
			}
		}
	}
	if checked < 20 {
		t.Fatalf("only %d labels inspected; expected the full metric surface", checked)
	}
	t.Logf("inspected %d label declarations across %d metrics", checked, len(matches))
}

// TestRegisteredMetricsAvoidReservedLabels cross-checks at runtime, catching
// any metric registered from outside metrics.go that the source scan cannot
// see. It only inspects families that actually carry data.
func TestRegisteredMetricsAvoidReservedLabels(t *testing.T) {
	// Register is idempotent-unsafe (MustRegister panics on a duplicate), so
	// tolerate an already-registered default registry.
	func() {
		defer func() { _ = recover() }()
		Register()
	}()

	families, err := prometheus.DefaultGatherer.Gather()
	if err != nil {
		t.Fatalf("gather: %v", err)
	}
	for _, family := range families {
		if !strings.HasPrefix(family.GetName(), "githubsts_") {
			continue
		}
		for _, metric := range family.GetMetric() {
			for _, label := range metric.GetLabel() {
				if why, reserved := reservedLabels[label.GetName()]; reserved {
					t.Errorf("registered metric %s exposes reserved label %q (%s)",
						family.GetName(), label.GetName(), why)
				}
			}
		}
	}
}
