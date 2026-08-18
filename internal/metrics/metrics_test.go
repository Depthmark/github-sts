package metrics

import (
	"testing"

	dto "github.com/prometheus/client_model/go"
)

func TestBundleEnforcementRequiredMetric(t *testing.T) {
	for _, value := range []float64{0, 1} {
		BundleEnforcementRequired.Set(value)
		metric := &dto.Metric{}
		if err := BundleEnforcementRequired.Write(metric); err != nil {
			t.Fatalf("Write: %v", err)
		}
		if got := metric.GetGauge().GetValue(); got != value {
			t.Fatalf("metric = %v, want %v", got, value)
		}
	}
}
