package github

import (
	"testing"
)

func TestParseLinkNext(t *testing.T) {
	tests := []struct {
		name string
		link string
		want string
	}{
		{
			name: "with next",
			link: `<https://api.github.com/app/installations?page=2>; rel="next", <https://api.github.com/app/installations?page=5>; rel="last"`,
			want: "https://api.github.com/app/installations?page=2",
		},
		{
			name: "no next",
			link: `<https://api.github.com/app/installations?page=5>; rel="last"`,
			want: "",
		},
		{
			name: "empty",
			link: "",
			want: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseLinkNext(tt.link)
			if got != tt.want {
				t.Errorf("parseLinkNext() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRateLimitPoller_StartStop(t *testing.T) {
	// Verify start/stop lifecycle doesn't panic.
	poller := NewRateLimitPoller(nil, "http://localhost", 10*60*1e9)
	poller.Start()
	poller.Stop()
}
