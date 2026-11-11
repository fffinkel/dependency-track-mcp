// Package tools defines the MCP tools. Each tool answers one question about
// a Dependency-Track portfolio and makes a fixed, small number of requests to
// Dependency-Track; see CONTRIBUTING.md for the rules a new tool must meet.
package tools

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/fffinkel/dependency-track-mcp/internal/dtrack"
)

// Config is what the tools need to run.
type Config struct {
	Client *dtrack.Client
	// Default is the credential used when a request carries none. It is the
	// only credential over stdio. Over HTTP it is optional: when empty, every
	// request must bring its own.
	Default dtrack.Credential
}

type registry struct {
	client *dtrack.Client
	def    dtrack.Credential
}

// Register adds every tool to the server.
func Register(server *mcp.Server, cfg Config) {
	r := &registry{client: cfg.Client, def: cfg.Default}

	mcp.AddTool(server, tool("find_projects", "Find projects",
		"Find Dependency-Track projects by name or part of a name (case-insensitive), with each project's vulnerability and policy violation counts. "+
			"Use this first to get the project UUID the other tools need. A name can have several projects, one per version. "+
			"Cost: 1 request to Dependency-Track."), r.findProjects)

	mcp.AddTool(server, tool("get_project_summary", "Project summary",
		"Summarize one project: vulnerability counts by severity, policy violations by state, component counts and when its SBOM was last imported. "+
			"Cost: at most 2 requests to Dependency-Track."), r.projectSummary)

	mcp.AddTool(server, tool("list_project_findings", "Project findings",
		"List the vulnerabilities found in one project, most severe first, with the affected component, CVSS, EPSS and whether the vulnerability is known to be exploited (KEV). "+
			"Filter with min_severity, kev_only and min_epss. The result says how many findings matched and whether the project's findings were read completely. "+
			fmt.Sprintf("Cost: at most %d requests to Dependency-Track (%d findings read).", dtrack.MaxFindingPages, dtrack.MaxFindingPages*dtrack.PageSize)), r.projectFindings)

	mcp.AddTool(server, tool("list_project_policy_violations", "Project policy violations",
		"List the policy violations of one project, failing policies first, with the policy, the component and the condition that matched. "+
			"Cost: 1 request to Dependency-Track."), r.projectViolations)

	mcp.AddTool(server, tool("get_vulnerability", "Vulnerability details",
		"Describe one vulnerability by ID (for example CVE-2024-3094 or GHSA-xxxx-xxxx-xxxx): severity, CVSS, EPSS, KEV status, weaknesses and other IDs it is known by. Use list_affected_projects for where it is present. "+
			"Cost: 1 request to Dependency-Track."), r.vulnerability)

	mcp.AddTool(server, tool("list_affected_projects", "Projects affected by a vulnerability",
		"List the projects that carry one vulnerability, by ID. Answers \"where are we exposed to this CVE?\" without reading the portfolio project by project. "+
			"Cost: 1 request to Dependency-Track."), r.affectedProjects)

	mcp.AddTool(server, tool("get_portfolio_summary", "Portfolio summary",
		"Summarize the whole portfolio from the metrics Dependency-Track precomputes: projects, vulnerable projects, vulnerabilities by severity and policy violations by state. "+
			"Cost: 1 request to Dependency-Track."), r.portfolioSummary)
}

func tool(name, title, description string) *mcp.Tool {
	closedWorld := false
	return &mcp.Tool{
		Name:        name,
		Title:       title,
		Description: description,
		Annotations: &mcp.ToolAnnotations{
			Title:          title,
			ReadOnlyHint:   true,
			IdempotentHint: true,
			OpenWorldHint:  &closedWorld,
		},
	}
}

// credential picks the Dependency-Track credential for one tool call: the
// one the HTTP request carried, else the configured default. Passing the
// caller's own credential through is what keeps Dependency-Track's
// permissions and portfolio access control in force.
func (r *registry) credential(req *mcp.CallToolRequest) dtrack.Credential {
	if req != nil && req.Extra != nil && req.Extra.Header != nil {
		if key := strings.TrimSpace(req.Extra.Header.Get("X-Api-Key")); key != "" {
			return dtrack.Credential{APIKey: key}
		}
		if auth := req.Extra.Header.Get("Authorization"); len(auth) > 7 && strings.EqualFold(auth[:7], "Bearer ") {
			if token := strings.TrimSpace(auth[7:]); token != "" {
				return dtrack.Credential{Bearer: token}
			}
		}
	}
	return r.def
}

// clamp returns n limited to [1, max], or def when n is not positive.
func clamp(n, def, max int) int {
	if n <= 0 {
		return def
	}
	if n > max {
		return max
	}
	return n
}

// ---- find_projects ----

type findProjectsIn struct {
	Name            string `json:"name" jsonschema:"Project name or part of it. Must be the exact name when version is given"`
	Version         string `json:"version,omitempty" jsonschema:"Exact project version, with the exact name. Omit to search by name across versions"`
	IncludeInactive bool   `json:"include_inactive,omitempty" jsonschema:"Also return inactive projects. Default false"`
	Limit           int    `json:"limit,omitempty" jsonschema:"Maximum projects to return. Default 20, maximum 50"`
}

type projectOut struct {
	UUID                 string   `json:"uuid"`
	Name                 string   `json:"name"`
	Version              string   `json:"version,omitempty"`
	Active               bool     `json:"active"`
	IsLatest             bool     `json:"is_latest"`
	Tags                 []string `json:"tags"`
	Critical             int      `json:"critical"`
	High                 int      `json:"high"`
	Medium               int      `json:"medium"`
	Low                  int      `json:"low"`
	PolicyViolationsFail int      `json:"policy_violations_fail"`
	PolicyViolationsWarn int      `json:"policy_violations_warn"`
}

type findProjectsOut struct {
	Projects []projectOut `json:"projects"`
	// Total is how many projects match in Dependency-Track.
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

func toProjectOut(p dtrack.Project) projectOut {
	out := projectOut{
		UUID:     p.UUID,
		Name:     p.Name,
		Version:  p.Version,
		Active:   p.IsActive(),
		IsLatest: p.IsLatest,
		Tags:     p.TagNames(),
	}
	if m := p.Metrics; m != nil {
		out.Critical, out.High, out.Medium, out.Low = m.Critical, m.High, m.Medium, m.Low
		out.PolicyViolationsFail, out.PolicyViolationsWarn = m.PolicyViolationsFail, m.PolicyViolationsWarn
	}
	return out
}

func (r *registry) findProjects(ctx context.Context, req *mcp.CallToolRequest, in findProjectsIn) (*mcp.CallToolResult, findProjectsOut, error) {
	out := findProjectsOut{Projects: []projectOut{}}
	name := strings.TrimSpace(in.Name)
	if name == "" {
		return nil, out, errors.New("name is required")
	}
	cred := r.credential(req)

	if in.Version != "" {
		p, err := r.client.LookupProject(ctx, cred, name, in.Version)
		if dtrack.IsNotFound(err) {
			return nil, out, nil
		}
		if err != nil {
			return nil, out, err
		}
		if p.IsActive() || in.IncludeInactive {
			out.Projects = append(out.Projects, toProjectOut(p))
			out.Total = 1
		}
		return nil, out, nil
	}

	page, err := r.client.FindProjects(ctx, cred, name, in.IncludeInactive, clamp(in.Limit, 20, 50))
	if err != nil {
		return nil, out, err
	}
	for _, p := range page.Items {
		out.Projects = append(out.Projects, toProjectOut(p))
	}
	out.Total = max(page.Total, len(out.Projects))
	out.Truncated = !page.Complete
	return nil, out, nil
}

// ---- get_project_summary ----

type projectIn struct {
	ProjectUUID string `json:"project_uuid" jsonschema:"Project UUID, from find_projects"`
}

type projectSummaryOut struct {
	Project              projectOut `json:"project"`
	Classifier           string     `json:"classifier,omitempty"`
	Unassigned           int        `json:"unassigned_severity"`
	Vulnerabilities      int        `json:"vulnerabilities"`
	Components           int        `json:"components"`
	VulnerableComponents int        `json:"vulnerable_components"`
	Suppressed           int        `json:"suppressed_findings"`
	FindingsAudited      int        `json:"findings_audited"`
	FindingsUnaudited    int        `json:"findings_unaudited"`
	PolicyViolationsInfo int        `json:"policy_violations_info"`
	InheritedRiskScore   float64    `json:"inherited_risk_score"`
	LastBomImport        string     `json:"last_bom_import,omitempty"`
}

func (r *registry) projectSummary(ctx context.Context, req *mcp.CallToolRequest, in projectIn) (*mcp.CallToolResult, projectSummaryOut, error) {
	var out projectSummaryOut
	uuid := strings.TrimSpace(in.ProjectUUID)
	if uuid == "" {
		return nil, out, errors.New("project_uuid is required")
	}
	cred := r.credential(req)

	p, err := r.client.Project(ctx, cred, uuid)
	if err != nil {
		return nil, out, err
	}
	if p.Metrics == nil {
		m, err := r.client.ProjectMetrics(ctx, cred, uuid)
		if err != nil {
			return nil, out, err
		}
		p.Metrics = &m
	}
	m := p.Metrics
	out = projectSummaryOut{
		Project:              toProjectOut(p),
		Classifier:           p.Classifier,
		Unassigned:           m.Unassigned,
		Vulnerabilities:      m.Vulnerabilities,
		Components:           m.Components,
		VulnerableComponents: m.VulnerableComponents,
		Suppressed:           m.Suppressed,
		FindingsAudited:      m.FindingsAudited,
		FindingsUnaudited:    m.FindingsUnaudited,
		PolicyViolationsInfo: m.PolicyViolationsInfo,
		InheritedRiskScore:   m.InheritedRiskScore,
		LastBomImport:        p.LastBomImport.String(),
	}
	return nil, out, nil
}

// ---- list_project_findings ----

type findingsIn struct {
	ProjectUUID       string  `json:"project_uuid" jsonschema:"Project UUID, from find_projects"`
	MinSeverity       string  `json:"min_severity,omitempty" jsonschema:"Only findings at or above this severity: CRITICAL, HIGH, MEDIUM or LOW. Default: all"`
	KEVOnly           bool    `json:"kev_only,omitempty" jsonschema:"Only vulnerabilities in the CISA Known Exploited Vulnerabilities catalog. Default false"`
	MinEPSS           float64 `json:"min_epss,omitempty" jsonschema:"Only findings whose EPSS score (0 to 1) is at least this. Default: no filter"`
	IncludeSuppressed bool    `json:"include_suppressed,omitempty" jsonschema:"Also return findings suppressed in Dependency-Track. Default false"`
	Limit             int     `json:"limit,omitempty" jsonschema:"Maximum findings to return. Default 25, maximum 100"`
}

type findingOut struct {
	VulnID         string   `json:"vuln_id"`
	Source         string   `json:"source"`
	Severity       string   `json:"severity"`
	CVSS           *float64 `json:"cvss,omitempty"`
	EPSS           *float64 `json:"epss,omitempty"`
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
	KEV            bool     `json:"kev"`
	Aliases        []string `json:"aliases,omitempty"`
	Component      string   `json:"component"`
	Version        string   `json:"version,omitempty"`
	PURL           string   `json:"purl,omitempty"`
	LatestVersion  string   `json:"latest_version,omitempty"`
	AnalysisState  string   `json:"analysis_state,omitempty"`
	Suppressed     bool     `json:"suppressed"`
}

type findingsOut struct {
	Findings []findingOut `json:"findings"`
	// Matched is how many of the findings read passed the filters.
	Matched int `json:"matched"`
	// Read is how many of the project's findings were read.
	Read int `json:"read"`
	// Complete is false when the project has more findings than one call
	// reads. Matched and Findings then cover only the findings read.
	Complete bool   `json:"complete"`
	Note     string `json:"note,omitempty"`
}

func (r *registry) projectFindings(ctx context.Context, req *mcp.CallToolRequest, in findingsIn) (*mcp.CallToolResult, findingsOut, error) {
	out := findingsOut{Findings: []findingOut{}}
	uuid := strings.TrimSpace(in.ProjectUUID)
	if uuid == "" {
		return nil, out, errors.New("project_uuid is required")
	}
	maxRank := 5
	if in.MinSeverity != "" {
		maxRank = dtrack.SeverityRank(in.MinSeverity)
		if maxRank > 3 {
			return nil, out, fmt.Errorf("min_severity %q is not one of CRITICAL, HIGH, MEDIUM, LOW", in.MinSeverity)
		}
	}
	if in.MinEPSS < 0 || in.MinEPSS > 1 {
		return nil, out, errors.New("min_epss must be between 0 and 1")
	}

	page, err := r.client.ProjectFindings(ctx, r.credential(req), uuid, in.IncludeSuppressed)
	if err != nil {
		return nil, out, err
	}

	matched := make([]dtrack.Finding, 0, len(page.Items))
	for _, f := range page.Items {
		v := f.Vulnerability
		switch {
		case dtrack.SeverityRank(v.Severity) > maxRank:
		case in.KEVOnly && !v.IsKEV:
		case in.MinEPSS > 0 && (v.EPSSScore == nil || *v.EPSSScore < in.MinEPSS):
		case f.Analysis.IsSuppressed && !in.IncludeSuppressed:
		default:
			matched = append(matched, f)
		}
	}

	// Most urgent first: known exploited, then severity, then EPSS.
	sort.SliceStable(matched, func(i, j int) bool {
		a, b := matched[i].Vulnerability, matched[j].Vulnerability
		if a.IsKEV != b.IsKEV {
			return a.IsKEV
		}
		if ra, rb := dtrack.SeverityRank(a.Severity), dtrack.SeverityRank(b.Severity); ra != rb {
			return ra < rb
		}
		return deref(a.EPSSScore) > deref(b.EPSSScore)
	})

	out.Matched = len(matched)
	out.Read = len(page.Items)
	out.Complete = page.Complete
	if !page.Complete {
		out.Note = fmt.Sprintf("Only the first %d findings of this project were read; it has more. Results cover the findings read.", len(page.Items))
		if page.Total > len(page.Items) {
			out.Note = fmt.Sprintf("Only the first %d of %d findings of this project were read. Results cover the findings read.", len(page.Items), page.Total)
		}
	}

	limit := clamp(in.Limit, 25, 100)
	if len(matched) > limit {
		matched = matched[:limit]
	}
	for _, f := range matched {
		v := f.Vulnerability
		out.Findings = append(out.Findings, findingOut{
			VulnID:         v.VulnID,
			Source:         v.Source,
			Severity:       v.Severity,
			CVSS:           v.CVSS(),
			EPSS:           v.EPSSScore,
			EPSSPercentile: v.EPSSPercentile,
			KEV:            v.IsKEV,
			Aliases:        v.AliasIDs(),
			Component:      f.Component.Name,
			Version:        f.Component.Version,
			PURL:           f.Component.PURL,
			LatestVersion:  f.Component.LatestVersion,
			AnalysisState:  f.Analysis.State,
			Suppressed:     f.Analysis.IsSuppressed,
		})
	}
	return nil, out, nil
}

func deref(f *float64) float64 {
	if f == nil {
		return 0
	}
	return *f
}

// ---- list_project_policy_violations ----

type violationsIn struct {
	ProjectUUID       string `json:"project_uuid" jsonschema:"Project UUID, from find_projects"`
	IncludeSuppressed bool   `json:"include_suppressed,omitempty" jsonschema:"Also return violations suppressed in Dependency-Track. Default false"`
	Limit             int    `json:"limit,omitempty" jsonschema:"Maximum violations to return. Default 25, maximum 100"`
}

type violationOut struct {
	Policy        string `json:"policy"`
	State         string `json:"state"`
	Type          string `json:"type"`
	Condition     string `json:"condition,omitempty"`
	Component     string `json:"component"`
	Version       string `json:"version,omitempty"`
	PURL          string `json:"purl,omitempty"`
	OccurredAt    string `json:"occurred_at,omitempty"`
	AnalysisState string `json:"analysis_state,omitempty"`
	Suppressed    bool   `json:"suppressed"`
}

type violationsOut struct {
	Violations []violationOut `json:"violations"`
	// Total is how many violations the project has in Dependency-Track.
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

func stateRank(state string) int {
	switch strings.ToUpper(state) {
	case "FAIL":
		return 0
	case "WARN":
		return 1
	}
	return 2
}

func (r *registry) projectViolations(ctx context.Context, req *mcp.CallToolRequest, in violationsIn) (*mcp.CallToolResult, violationsOut, error) {
	out := violationsOut{Violations: []violationOut{}}
	uuid := strings.TrimSpace(in.ProjectUUID)
	if uuid == "" {
		return nil, out, errors.New("project_uuid is required")
	}

	page, err := r.client.ProjectViolations(ctx, r.credential(req), uuid, in.IncludeSuppressed, clamp(in.Limit, 25, 100))
	if err != nil {
		return nil, out, err
	}
	sort.SliceStable(page.Items, func(i, j int) bool {
		return stateRank(page.Items[i].PolicyCondition.Policy.ViolationState) < stateRank(page.Items[j].PolicyCondition.Policy.ViolationState)
	})
	for _, v := range page.Items {
		cond := v.PolicyCondition
		vo := violationOut{
			Policy:     cond.Policy.Name,
			State:      cond.Policy.ViolationState,
			Type:       v.Type,
			Condition:  truncate(strings.Join(strings.Fields(cond.Subject+" "+cond.Operator+" "+cond.Value), " "), maxCondition),
			Component:  v.Component.Name,
			Version:    v.Component.Version,
			PURL:       v.Component.PURL,
			OccurredAt: v.Timestamp.String(),
		}
		if v.Analysis != nil {
			vo.AnalysisState = v.Analysis.State
			vo.Suppressed = v.Analysis.IsSuppressed
		}
		out.Violations = append(out.Violations, vo)
	}
	out.Total = max(page.Total, len(out.Violations))
	out.Truncated = !page.Complete
	return nil, out, nil
}

// ---- get_vulnerability / list_affected_projects ----

type vulnIn struct {
	VulnID string `json:"vuln_id" jsonschema:"Vulnerability ID, for example CVE-2024-3094 or GHSA-xxxx-xxxx-xxxx"`
	Source string `json:"source,omitempty" jsonschema:"Dependency-Track source of the record: NVD, GITHUB, OSV, SNYK, OSSINDEX, VULNDB or INTERNAL. Omit to infer it from the ID (CVE is NVD, GHSA is GITHUB)"`
}

func (in vulnIn) resolve() (source, id string, err error) {
	id = strings.TrimSpace(in.VulnID)
	if id == "" {
		return "", "", errors.New("vuln_id is required")
	}
	source = strings.ToUpper(strings.TrimSpace(in.Source))
	if source == "" {
		source = dtrack.SourceForID(id)
	}
	if source == "" {
		return "", "", fmt.Errorf("cannot tell the source of %q from its ID: pass source (NVD, GITHUB, OSV, SNYK, OSSINDEX, VULNDB or INTERNAL)", id)
	}
	return source, id, nil
}

// Free text from Dependency-Track is cut to these lengths (bytes) so one
// long field cannot crowd out the rest of a result.
const (
	maxDescription = 1200
	maxCondition   = 300
)

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return strings.ToValidUTF8(s[:max], "") + "…"
}

type vulnOut struct {
	VulnID         string   `json:"vuln_id"`
	Source         string   `json:"source"`
	Title          string   `json:"title,omitempty"`
	Description    string   `json:"description,omitempty"`
	Severity       string   `json:"severity"`
	CVSS           *float64 `json:"cvss,omitempty"`
	EPSS           *float64 `json:"epss,omitempty"`
	EPSSPercentile *float64 `json:"epss_percentile,omitempty"`
	KEV            bool     `json:"kev"`
	CWEs           []string `json:"cwes,omitempty"`
	Aliases        []string `json:"aliases,omitempty"`
	Published      string   `json:"published,omitempty"`
}

func (r *registry) vulnerability(ctx context.Context, req *mcp.CallToolRequest, in vulnIn) (*mcp.CallToolResult, vulnOut, error) {
	var out vulnOut
	source, id, err := in.resolve()
	if err != nil {
		return nil, out, err
	}
	v, err := r.client.Vulnerability(ctx, r.credential(req), source, id)
	if dtrack.IsNotFound(err) {
		return nil, out, fmt.Errorf("Dependency-Track has no %s record for %s. If it is known under another source (for example OSV or GITHUB), pass source", source, id)
	}
	if err != nil {
		return nil, out, err
	}

	out = vulnOut{
		VulnID:         v.VulnID,
		Source:         v.Source,
		Title:          v.Title,
		Description:    truncate(strings.TrimSpace(v.Description), maxDescription),
		Severity:       v.Severity,
		CVSS:           v.CVSS(),
		EPSS:           v.EPSSScore,
		EPSSPercentile: v.EPSSPercentile,
		KEV:            v.IsKEV,
		Aliases:        v.AliasIDs(),
		Published:      v.Published.String(),
	}
	for _, cwe := range v.CWEs {
		out.CWEs = append(out.CWEs, strings.TrimSpace(fmt.Sprintf("CWE-%d %s", cwe.ID, cwe.Name)))
	}
	return nil, out, nil
}

type affectedIn struct {
	VulnID          string `json:"vuln_id" jsonschema:"Vulnerability ID, for example CVE-2024-3094 or GHSA-xxxx-xxxx-xxxx"`
	Source          string `json:"source,omitempty" jsonschema:"Dependency-Track source of the record: NVD, GITHUB, OSV, SNYK, OSSINDEX, VULNDB or INTERNAL. Omit to infer it from the ID (CVE is NVD, GHSA is GITHUB)"`
	IncludeInactive bool   `json:"include_inactive,omitempty" jsonschema:"Also return inactive projects. Default false"`
	Limit           int    `json:"limit,omitempty" jsonschema:"Maximum projects to return. Default 50, maximum 100"`
}

type affectedProjectOut struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Active  bool   `json:"active"`
}

type affectedOut struct {
	VulnID   string               `json:"vuln_id"`
	Source   string               `json:"source"`
	Projects []affectedProjectOut `json:"projects"`
	// Total is how many projects carry the vulnerability in Dependency-Track.
	Total     int  `json:"total"`
	Truncated bool `json:"truncated"`
}

func (r *registry) affectedProjects(ctx context.Context, req *mcp.CallToolRequest, in affectedIn) (*mcp.CallToolResult, affectedOut, error) {
	out := affectedOut{Projects: []affectedProjectOut{}}
	source, id, err := vulnIn{VulnID: in.VulnID, Source: in.Source}.resolve()
	if err != nil {
		return nil, out, err
	}
	out.VulnID, out.Source = id, source

	page, err := r.client.AffectedProjects(ctx, r.credential(req), source, id, in.IncludeInactive, clamp(in.Limit, 50, 100))
	if dtrack.IsNotFound(err) {
		return nil, out, fmt.Errorf("Dependency-Track has no %s record for %s. If it is known under another source (for example OSV or GITHUB), pass source", source, id)
	}
	if err != nil {
		return nil, out, err
	}
	for _, p := range page.Items {
		active := p.Active == nil || *p.Active
		if !active && !in.IncludeInactive {
			continue
		}
		out.Projects = append(out.Projects, affectedProjectOut{UUID: p.UUID, Name: p.Name, Version: p.Version, Active: active})
	}
	out.Total = max(page.Total, len(out.Projects))
	out.Truncated = !page.Complete
	return nil, out, nil
}

// ---- get_portfolio_summary ----

type portfolioIn struct{}

type portfolioOut struct {
	Projects             int     `json:"projects"`
	VulnerableProjects   int     `json:"vulnerable_projects"`
	Components           int     `json:"components"`
	VulnerableComponents int     `json:"vulnerable_components"`
	Vulnerabilities      int     `json:"vulnerabilities"`
	Critical             int     `json:"critical"`
	High                 int     `json:"high"`
	Medium               int     `json:"medium"`
	Low                  int     `json:"low"`
	Unassigned           int     `json:"unassigned_severity"`
	Suppressed           int     `json:"suppressed_findings"`
	FindingsAudited      int     `json:"findings_audited"`
	FindingsUnaudited    int     `json:"findings_unaudited"`
	PolicyViolationsFail int     `json:"policy_violations_fail"`
	PolicyViolationsWarn int     `json:"policy_violations_warn"`
	PolicyViolationsInfo int     `json:"policy_violations_info"`
	InheritedRiskScore   float64 `json:"inherited_risk_score"`
	MeasuredAt           string  `json:"measured_at,omitempty"`
}

func (r *registry) portfolioSummary(ctx context.Context, req *mcp.CallToolRequest, _ portfolioIn) (*mcp.CallToolResult, portfolioOut, error) {
	m, err := r.client.PortfolioMetrics(ctx, r.credential(req))
	if err != nil {
		return nil, portfolioOut{}, err
	}
	return nil, portfolioOut{
		Projects:             m.Projects,
		VulnerableProjects:   m.VulnerableProjects,
		Components:           m.Components,
		VulnerableComponents: m.VulnerableComponents,
		Vulnerabilities:      m.Vulnerabilities,
		Critical:             m.Critical,
		High:                 m.High,
		Medium:               m.Medium,
		Low:                  m.Low,
		Unassigned:           m.Unassigned,
		Suppressed:           m.Suppressed,
		FindingsAudited:      m.FindingsAudited,
		FindingsUnaudited:    m.FindingsUnaudited,
		PolicyViolationsFail: m.PolicyViolationsFail,
		PolicyViolationsWarn: m.PolicyViolationsWarn,
		PolicyViolationsInfo: m.PolicyViolationsInfo,
		InheritedRiskScore:   m.InheritedRiskScore,
		MeasuredAt:           m.LastOccurrence.String(),
	}, nil
}
