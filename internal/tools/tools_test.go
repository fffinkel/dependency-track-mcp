package tools

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fffinkel/dependency-track-mcp/internal/dtrack"
)

// fakeDT is a stand-in Dependency-Track API server. It records every request
// so tests can assert on cost and on the credential that was sent.
type fakeDT struct {
	t        *testing.T
	findings int // findings the project has

	mu       sync.Mutex
	requests []*http.Request
}

func (f *fakeDT) seen() []*http.Request {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]*http.Request(nil), f.requests...)
}

func (f *fakeDT) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	f.mu.Lock()
	f.requests = append(f.requests, r.Clone(context.Background()))
	f.mu.Unlock()

	if r.Method != http.MethodGet {
		f.t.Errorf("non-GET request to Dependency-Track: %s %s", r.Method, r.URL.Path)
	}
	if r.Header.Get("X-Api-Key") == "" && r.Header.Get("Authorization") == "" {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}
	if r.Header.Get("X-Api-Key") == "no-access" {
		w.WriteHeader(http.StatusForbidden)
		return
	}

	q := r.URL.Query()
	switch r.URL.Path {
	case "/api/v1/project":
		if !strings.Contains("shop/api", q.Get("searchText")) {
			writeJSON(w, 0, []any{})
			return
		}
		writeJSON(w, 2, []any{
			map[string]any{"uuid": "p-1", "name": "shop/api", "version": "main", "active": true, "isLatest": true,
				"tags":    []any{map[string]any{"name": "tier:prod"}, map[string]any{"name": "owner:shop"}},
				"metrics": map[string]any{"critical": 1, "high": 2, "policyViolationsFail": 1}},
			map[string]any{"uuid": "p-2", "name": "shop/api", "version": "1.0", "active": true},
		})
	case "/api/v1/project/lookup":
		if q.Get("version") != "main" {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		writeJSON(w, -1, map[string]any{"uuid": "p-1", "name": "shop/api", "version": "main", "active": true})
	case "/api/v1/project/p-1":
		writeJSON(w, -1, map[string]any{"uuid": "p-1", "name": "shop/api", "version": "main", "classifier": "CONTAINER",
			"lastBomImport": 1767225600000})
	case "/api/v1/metrics/project/p-1/current":
		writeJSON(w, -1, map[string]any{"critical": 1, "high": 2, "components": 40, "vulnerabilities": 3})
	case "/api/v1/finding/project/p-1":
		page, _ := strconv.Atoi(q.Get("pageNumber"))
		size, _ := strconv.Atoi(q.Get("pageSize"))
		items := []any{}
		for i := (page - 1) * size; i < page*size && i < f.findings; i++ {
			items = append(items, finding(i))
		}
		writeJSON(w, f.findings, items)
	case "/api/v1/violation/project/p-1":
		writeJSON(w, 2, []any{
			violation("Standard", "WARN", "libb"),
			violation("Urgent", "FAIL", "liba"),
		})
	case "/api/v1/vulnerability/source/NVD/vuln/CVE-2024-0001":
		writeJSON(w, -1, map[string]any{"vulnId": "CVE-2024-0001", "source": "NVD", "severity": "CRITICAL",
			"description": strings.Repeat("x", 5000), "cvssV3BaseScore": 9.8, "epssScore": 0.9, "isKev": true,
			"cwes":      []any{map[string]any{"cweId": 79, "name": "XSS"}},
			"aliases":   []any{map[string]any{"cveId": "CVE-2024-0001", "ghsaId": "GHSA-aaaa-bbbb-cccc"}},
			"published": "2024-01-02T03:04:05Z"})
	case "/api/v1/vulnerability/source/NVD/vuln/CVE-2024-0001/projects":
		writeJSON(w, 2, []any{
			map[string]any{"uuid": "p-1", "name": "shop/api", "version": "main", "active": true},
			map[string]any{"uuid": "p-9", "name": "shop/web", "version": "main", "active": true},
		})
	case "/api/v1/metrics/portfolio/current":
		writeJSON(w, -1, map[string]any{"projects": 10, "vulnerableProjects": 4, "critical": 5, "policyViolationsFail": 2})
	default:
		w.WriteHeader(http.StatusNotFound)
	}
}

// finding i is LOW, except the last two, which are HIGH and a KEV CRITICAL,
// so sorting has to pull them from the end of the list.
func finding(i int) map[string]any {
	vuln := map[string]any{"vulnId": fmt.Sprintf("CVE-2024-%04d", i), "source": "NVD", "severity": "LOW", "epssScore": 0.01}
	switch i % 100 {
	case 98:
		vuln["severity"], vuln["epssScore"] = "HIGH", 0.5
	case 99:
		vuln["severity"], vuln["isKev"], vuln["cvssV4Score"] = "CRITICAL", true, 9.9
	}
	return map[string]any{
		"component":     map[string]any{"name": "lib", "version": "1.0." + strconv.Itoa(i), "purl": "pkg:npm/lib@1.0." + strconv.Itoa(i)},
		"vulnerability": vuln,
		"analysis":      map[string]any{"isSuppressed": false},
	}
}

func violation(policy, state, component string) map[string]any {
	return map[string]any{
		"type":      "SECURITY",
		"timestamp": 1767225600000,
		"component": map[string]any{"name": component, "version": "1.0"},
		"policyCondition": map[string]any{"subject": "SEVERITY", "operator": "IS", "value": "CRITICAL",
			"policy": map[string]any{"name": policy, "violationState": state}},
	}
}

func writeJSON(w http.ResponseWriter, total int, v any) {
	if total >= 0 {
		w.Header().Set("X-Total-Count", strconv.Itoa(total))
	}
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(v)
}

// setup starts a fake Dependency-Track, an MCP server with the tools, and an
// MCP client connected to it in memory.
func setup(t *testing.T, def dtrack.Credential) (*fakeDT, *mcp.ClientSession) {
	t.Helper()
	fake, server := newServer(t, def)

	ctx := context.Background()
	serverT, clientT := mcp.NewInMemoryTransports()
	if _, err := server.Connect(ctx, serverT, nil); err != nil {
		t.Fatal(err)
	}
	session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return fake, session
}

func newServer(t *testing.T, def dtrack.Credential) (*fakeDT, *mcp.Server) {
	t.Helper()
	fake := &fakeDT{t: t, findings: 3}
	upstream := httptest.NewServer(fake)
	t.Cleanup(upstream.Close)

	client, err := dtrack.New(dtrack.Options{BaseURL: upstream.URL})
	if err != nil {
		t.Fatal(err)
	}
	server := mcp.NewServer(&mcp.Implementation{Name: "test-server", Version: "0"}, nil)
	Register(server, Config{Client: client, Default: def})
	return fake, server
}

// call runs a tool and decodes its structured output into out. It returns
// the error text when the tool reported an error.
func call(t *testing.T, session *mcp.ClientSession, name string, args map[string]any, out any) string {
	t.Helper()
	res, err := session.CallTool(context.Background(), &mcp.CallToolParams{Name: name, Arguments: args})
	if err != nil {
		t.Fatalf("%s: protocol error: %v", name, err)
	}
	if res.IsError {
		text := ""
		for _, c := range res.Content {
			if tc, ok := c.(*mcp.TextContent); ok {
				text += tc.Text
			}
		}
		return text
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, out); err != nil {
		t.Fatalf("%s: decode output %s: %v", name, raw, err)
	}
	return ""
}

var key = dtrack.Credential{APIKey: "test-key"}

func TestToolsAreReadOnly(t *testing.T) {
	_, session := setup(t, key)
	res, err := session.ListTools(context.Background(), nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Tools) != 7 {
		t.Errorf("got %d tools, want 7", len(res.Tools))
	}
	for _, tool := range res.Tools {
		if tool.Annotations == nil || !tool.Annotations.ReadOnlyHint {
			t.Errorf("%s is not marked read-only", tool.Name)
		}
		if !strings.Contains(tool.Description, "Cost:") {
			t.Errorf("%s does not state its cost", tool.Name)
		}
	}
}

func TestFindProjects(t *testing.T) {
	fake, session := setup(t, key)

	var out findProjectsOut
	if msg := call(t, session, "find_projects", map[string]any{"name": "shop"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Projects) != 2 || out.Total != 2 || out.Truncated {
		t.Fatalf("got %+v", out)
	}
	first := out.Projects[0]
	if first.UUID != "p-1" || first.Critical != 1 || first.PolicyViolationsFail != 1 || strings.Join(first.Tags, ",") != "owner:shop,tier:prod" {
		t.Errorf("first project = %+v", first)
	}
	if !out.Projects[1].Active {
		t.Error("project without metrics should still be listed as active")
	}
	if got := fake.seen()[0].URL.Query().Get("excludeInactive"); got != "true" {
		t.Errorf("excludeInactive = %q, want true by default", got)
	}

	out = findProjectsOut{}
	if msg := call(t, session, "find_projects", map[string]any{"name": "nope"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Projects) != 0 || out.Projects == nil {
		t.Errorf("unknown name: got %+v, want an empty list", out)
	}

	out = findProjectsOut{}
	if msg := call(t, session, "find_projects", map[string]any{"name": "shop/api", "version": "gone"}, &out); msg != "" {
		t.Fatalf("unknown version should be an empty result, got error %q", msg)
	}
	if len(out.Projects) != 0 {
		t.Errorf("unknown version: got %+v", out)
	}

	if len(fake.seen()) != 3 {
		t.Errorf("3 calls made %d requests, want 1 each", len(fake.seen()))
	}
}

func TestProjectSummaryFallsBackToMetricsEndpoint(t *testing.T) {
	fake, session := setup(t, key)
	var out projectSummaryOut
	if msg := call(t, session, "get_project_summary", map[string]any{"project_uuid": "p-1"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Project.Critical != 1 || out.Components != 40 || out.Classifier != "CONTAINER" {
		t.Errorf("got %+v", out)
	}
	if out.LastBomImport != "2026-01-01T00:00:00Z" {
		t.Errorf("last_bom_import = %q", out.LastBomImport)
	}
	if n := len(fake.seen()); n != 2 {
		t.Errorf("made %d requests, want 2", n)
	}
}

func TestProjectFindingsSortsAndFilters(t *testing.T) {
	fake, session := setup(t, key)
	fake.findings = 250

	var out findingsOut
	if msg := call(t, session, "list_project_findings", map[string]any{"project_uuid": "p-1", "limit": 3}, &out); msg != "" {
		t.Fatal(msg)
	}
	if !out.Complete || out.Read != 250 || out.Matched != 250 || len(out.Findings) != 3 {
		t.Fatalf("complete=%v read=%d matched=%d returned=%d", out.Complete, out.Read, out.Matched, len(out.Findings))
	}
	if !out.Findings[0].KEV || out.Findings[0].Severity != "CRITICAL" || out.Findings[0].CVSS == nil {
		t.Errorf("first finding should be the KEV critical, got %+v", out.Findings[0])
	}
	if n := len(fake.seen()); n != 3 {
		t.Errorf("250 findings took %d requests, want 3", n)
	}

	out = findingsOut{}
	if msg := call(t, session, "list_project_findings", map[string]any{"project_uuid": "p-1", "min_severity": "high"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Matched != 4 { // findings 98, 99, 198, 199
		t.Errorf("min_severity=high matched %d, want 4", out.Matched)
	}

	out = findingsOut{}
	if msg := call(t, session, "list_project_findings", map[string]any{"project_uuid": "p-1", "kev_only": true}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Matched != 2 {
		t.Errorf("kev_only matched %d, want 2", out.Matched)
	}

	if msg := call(t, session, "list_project_findings", map[string]any{"project_uuid": "p-1", "min_severity": "urgent"}, &out); !strings.Contains(msg, "min_severity") {
		t.Errorf("bad min_severity: got %q", msg)
	}
}

func TestProjectFindingsStopsAtTheRequestCap(t *testing.T) {
	fake, session := setup(t, key)
	fake.findings = 5000

	var out findingsOut
	if msg := call(t, session, "list_project_findings", map[string]any{"project_uuid": "p-1"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if n := len(fake.seen()); n != dtrack.MaxFindingPages {
		t.Errorf("made %d requests, want the cap of %d", n, dtrack.MaxFindingPages)
	}
	if out.Complete || out.Read != dtrack.MaxFindingPages*dtrack.PageSize {
		t.Errorf("complete=%v read=%d", out.Complete, out.Read)
	}
	if !strings.Contains(out.Note, "1000 of 5000") {
		t.Errorf("note = %q, want it to say how much was read", out.Note)
	}
}

func TestProjectViolationsFailFirst(t *testing.T) {
	_, session := setup(t, key)
	var out violationsOut
	if msg := call(t, session, "list_project_policy_violations", map[string]any{"project_uuid": "p-1"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Violations) != 2 || out.Total != 2 {
		t.Fatalf("got %+v", out)
	}
	v := out.Violations[0]
	if v.State != "FAIL" || v.Policy != "Urgent" || v.Condition != "SEVERITY IS CRITICAL" || v.OccurredAt != "2026-01-01T00:00:00Z" {
		t.Errorf("first violation = %+v", v)
	}
}

func TestVulnerability(t *testing.T) {
	_, session := setup(t, key)
	var out vulnOut
	if msg := call(t, session, "get_vulnerability", map[string]any{"vuln_id": "CVE-2024-0001"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Source != "NVD" || !out.KEV || out.CVSS == nil || *out.CVSS != 9.8 {
		t.Errorf("got %+v", out)
	}
	if len(out.Description) > maxDescription+4 {
		t.Errorf("description is %d bytes, want it cut to about %d", len(out.Description), maxDescription)
	}
	if len(out.Aliases) != 1 || out.Aliases[0] != "GHSA-aaaa-bbbb-cccc" {
		t.Errorf("aliases = %v, want only the GHSA", out.Aliases)
	}
	if len(out.CWEs) != 1 || out.CWEs[0] != "CWE-79 XSS" {
		t.Errorf("cwes = %v", out.CWEs)
	}
	if out.Published != "2024-01-02T03:04:05Z" {
		t.Errorf("got %+v", out)
	}

	if msg := call(t, session, "get_vulnerability", map[string]any{"vuln_id": "CVE-1999-9999"}, &out); !strings.Contains(msg, "no NVD record") {
		t.Errorf("unknown CVE: got %q", msg)
	}
	if msg := call(t, session, "get_vulnerability", map[string]any{"vuln_id": "XYZ-1"}, &out); !strings.Contains(msg, "pass source") {
		t.Errorf("unknown ID shape: got %q", msg)
	}
}

func TestAffectedProjects(t *testing.T) {
	fake, session := setup(t, key)
	var out affectedOut
	if msg := call(t, session, "list_affected_projects", map[string]any{"vuln_id": "CVE-2024-0001"}, &out); msg != "" {
		t.Fatal(msg)
	}
	if len(out.Projects) != 2 || out.Total != 2 || out.Truncated || out.Source != "NVD" {
		t.Errorf("got %+v", out)
	}
	if n := len(fake.seen()); n != 1 {
		t.Errorf("made %d requests, want 1", n)
	}
}

func TestPortfolioSummary(t *testing.T) {
	_, session := setup(t, key)
	var out portfolioOut
	if msg := call(t, session, "get_portfolio_summary", nil, &out); msg != "" {
		t.Fatal(msg)
	}
	if out.Projects != 10 || out.VulnerableProjects != 4 || out.Critical != 5 || out.PolicyViolationsFail != 2 {
		t.Errorf("got %+v", out)
	}
}

func TestErrorsReachTheModel(t *testing.T) {
	_, session := setup(t, dtrack.Credential{APIKey: "no-access"})
	var out portfolioOut
	if msg := call(t, session, "get_portfolio_summary", nil, &out); !strings.Contains(msg, "403") {
		t.Errorf("forbidden: got %q", msg)
	}

	fake, session := setup(t, dtrack.Credential{})
	if msg := call(t, session, "get_portfolio_summary", nil, &out); !strings.Contains(msg, "no Dependency-Track credential") {
		t.Errorf("no credential: got %q", msg)
	}
	if n := len(fake.seen()); n != 0 {
		t.Errorf("made %d requests without a credential, want 0", n)
	}
}

// headerTransport adds headers to every request, the way an MCP client
// configured with custom headers does.
type headerTransport struct{ header http.Header }

func (h headerTransport) RoundTrip(r *http.Request) (*http.Response, error) {
	r = r.Clone(r.Context())
	for k, v := range h.header {
		r.Header[k] = v
	}
	return http.DefaultTransport.RoundTrip(r)
}

// Over HTTP the caller's own credential must reach Dependency-Track, so that
// Dependency-Track decides what the caller may see.
func TestHTTPForwardsTheCallersCredential(t *testing.T) {
	tests := []struct {
		name       string
		def        dtrack.Credential
		header     http.Header
		wantKey    string
		wantBearer string
		wantErr    string
	}{
		{name: "caller API key wins over the default", def: key, header: http.Header{"X-Api-Key": {"callers-key"}}, wantKey: "callers-key"},
		{name: "caller bearer token", header: http.Header{"Authorization": {"Bearer callers-token"}}, wantBearer: "Bearer callers-token"},
		{name: "default when the caller sends none", def: key, wantKey: "test-key"},
		{name: "no credential at all", wantErr: "no Dependency-Track credential"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake, server := newServer(t, tc.def)
			handler := mcp.NewStreamableHTTPHandler(func(*http.Request) *mcp.Server { return server },
				&mcp.StreamableHTTPOptions{Stateless: true, JSONResponse: true})
			front := httptest.NewServer(handler)
			t.Cleanup(front.Close)

			session, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(context.Background(),
				&mcp.StreamableClientTransport{Endpoint: front.URL, HTTPClient: &http.Client{Transport: headerTransport{tc.header}}}, nil)
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = session.Close() })

			var out portfolioOut
			msg := call(t, session, "get_portfolio_summary", nil, &out)
			if tc.wantErr != "" {
				if !strings.Contains(msg, tc.wantErr) {
					t.Fatalf("got %q, want an error containing %q", msg, tc.wantErr)
				}
				return
			}
			if msg != "" {
				t.Fatal(msg)
			}
			reqs := fake.seen()
			if len(reqs) != 1 {
				t.Fatalf("made %d requests, want 1", len(reqs))
			}
			if got := reqs[0].Header.Get("X-Api-Key"); got != tc.wantKey {
				t.Errorf("X-Api-Key = %q, want %q", got, tc.wantKey)
			}
			if got := reqs[0].Header.Get("Authorization"); got != tc.wantBearer {
				t.Errorf("Authorization = %q, want %q", got, tc.wantBearer)
			}
		})
	}
}
