package scan

import (
	"context"
	"fmt"
	"testing"

	"github.com/TMHSDigital/subenum/internal/dns"
)

func TestVerify(t *testing.T) {
	want := map[string]dns.Outcome{
		"a.example.com": dns.OutcomeFound,
		"b.example.com": dns.OutcomeNXDomain,
		"c.example.com": dns.OutcomeTimeout,
	}
	cfg := Config{
		Concurrency: 2,
		Exclude:     []string{"skip.example.com"},
		resolveHook: func(_ context.Context, name string) ([]dns.Record, dns.Outcome) {
			if name == "skip.example.com" {
				t.Error("an excluded name was looked up")
			}
			return nil, want[name]
		},
	}
	got, _ := Verify(context.Background(), cfg, []string{"a.example.com", "b.example.com", "c.example.com", "skip.example.com"})
	if len(got) != len(want) {
		t.Fatalf("got %d outcomes, want %d: %v", len(got), len(want), got)
	}
	for name, o := range want {
		if got[name] != o {
			t.Errorf("%s: %v, want %v", name, got[name], o)
		}
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got, _ = Verify(ctx, cfg, []string{"a.example.com", "b.example.com"})
	for name, o := range got {
		if o != dns.OutcomeCanceled && o != dns.OutcomeFound {
			t.Errorf("cancelled: %s = %v", name, o)
		}
	}
}

// TestVerifyCancelledMidwayReportsEveryName covers #151: names never handed
// to a worker are reported cancelled, not left out (which reads as found).
func TestVerifyCancelledMidwayReportsEveryName(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	cfg := Config{
		Concurrency: 1,
		Exclude:     []string{"skip.example.com"},
		resolveHook: func(context.Context, string) ([]dns.Record, dns.Outcome) {
			cancel()
			return nil, dns.OutcomeNXDomain
		},
	}
	names := []string{"skip.example.com"}
	for i := range 50 {
		names = append(names, fmt.Sprintf("n%d.example.com", i))
	}
	got, _ := Verify(ctx, cfg, names)
	if len(got) != len(names)-1 {
		t.Fatalf("got %d outcomes, want %d (every name but the excluded one)", len(got), len(names)-1)
	}
	if _, ok := got["skip.example.com"]; ok {
		t.Error("the excluded name has an outcome")
	}
	for name, o := range got {
		if o == dns.OutcomeFound {
			t.Errorf("%s reported found after cancellation", name)
		}
	}
}
