package dtrack

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func TestNewValidatesTheURL(t *testing.T) {
	for _, bad := range []string{"", "dtrack.example.com", "ftp://dtrack.example.com", "https://"} {
		if _, err := New(Options{BaseURL: bad}); err == nil {
			t.Errorf("New(%q) succeeded, want an error", bad)
		}
	}
	c, err := New(Options{BaseURL: "https://dtrack.example.com/api/"})
	if err != nil {
		t.Fatal(err)
	}
	if got := c.base.String(); got != "https://dtrack.example.com" {
		t.Errorf("base = %q, want the /api suffix dropped", got)
	}
}

func TestErrorsDoNotLeakTheCredential(t *testing.T) {
	c, err := New(Options{BaseURL: "http://127.0.0.1:1", Timeout: time.Second})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.PortfolioMetrics(context.Background(), Credential{APIKey: "s3cret"})
	if err == nil {
		t.Fatal("want a connection error")
	}
	if strings.Contains(err.Error(), "s3cret") {
		t.Errorf("error contains the API key: %v", err)
	}
}

func TestListOnServerThatIgnoresPaging(t *testing.T) {
	// Older Dependency-Track versions return every finding of a project in
	// one response, whatever page was asked for.
	var requests atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		items := make([]map[string]any, 250)
		for i := range items {
			items[i] = map[string]any{"vulnerability": map[string]any{"vulnId": fmt.Sprintf("CVE-%d", i)}}
		}
		w.Header().Set("X-Total-Count", "250")
		_ = json.NewEncoder(w).Encode(items)
	}))
	defer srv.Close()

	c, err := New(Options{BaseURL: srv.URL})
	if err != nil {
		t.Fatal(err)
	}
	page, err := c.ProjectFindings(context.Background(), Credential{APIKey: "k"}, "p-1", false)
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 250 || !page.Complete || requests.Load() != 1 {
		t.Errorf("items=%d complete=%v requests=%d, want 250, true, 1", len(page.Items), page.Complete, requests.Load())
	}
}

func TestMaxConcurrencyBoundsRequestsInFlight(t *testing.T) {
	var inFlight, peak atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := inFlight.Add(1)
		for {
			p := peak.Load()
			if n <= p || peak.CompareAndSwap(p, n) {
				break
			}
		}
		time.Sleep(20 * time.Millisecond)
		inFlight.Add(-1)
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()

	c, err := New(Options{BaseURL: srv.URL, MaxConcurrency: 2})
	if err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 8)
	for range 8 {
		go func() {
			_, err := c.PortfolioMetrics(context.Background(), Credential{APIKey: "k"})
			done <- err
		}()
	}
	for range 8 {
		if err := <-done; err != nil {
			t.Fatal(err)
		}
	}
	if got := peak.Load(); got > 2 {
		t.Errorf("%d requests in flight at once, want at most 2", got)
	}
}

func TestTimeDecoding(t *testing.T) {
	tests := map[string]string{
		`1767225600000`:          "2026-01-01T00:00:00Z",
		`"2024-01-02T03:04:05Z"`: "2024-01-02T03:04:05Z",
		`null`:                   "",
		`"not a date"`:           "",
	}
	for in, want := range tests {
		var got Time
		if err := json.Unmarshal([]byte(in), &got); err != nil {
			t.Errorf("%s: %v", in, err)
		}
		if got.String() != want {
			t.Errorf("%s decoded to %q, want %q", in, got.String(), want)
		}
	}
}

func TestSourceForID(t *testing.T) {
	tests := map[string]string{
		"CVE-2024-3094":       "NVD",
		"cve-2024-3094":       "NVD",
		"GHSA-aaaa-bbbb-cccc": "GITHUB",
		"GO-2024-0001":        "OSV",
		"SNYK-JS-FOO-1":       "SNYK",
		"whatever":            "",
	}
	for id, want := range tests {
		if got := SourceForID(id); got != want {
			t.Errorf("SourceForID(%q) = %q, want %q", id, got, want)
		}
	}
}
