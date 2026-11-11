package dtrack

import (
	"context"
	"net/url"
	"strconv"
	"strings"
)

// MaxFindingPages bounds how much of one project's findings a single call
// reads: MaxFindingPages * PageSize findings.
const MaxFindingPages = 10

// FindProjects returns projects whose name contains text (case-insensitive),
// up to limit. One request.
func (c *Client) FindProjects(ctx context.Context, cred Credential, text string, includeInactive bool, limit int) (Page[Project], error) {
	q := url.Values{}
	q.Set("searchText", text)
	if !includeInactive {
		q.Set("excludeInactive", "true")
	}
	return list[Project](ctx, c, cred, "v1/project", q, limit, 1)
}

// LookupProject returns the project with exactly this name and version. One
// request.
func (c *Client) LookupProject(ctx context.Context, cred Credential, name, version string) (Project, error) {
	q := url.Values{}
	q.Set("name", name)
	q.Set("version", version)
	var p Project
	_, err := c.get(ctx, cred, "v1/project/lookup", q, &p)
	return p, err
}

// Project returns one project by UUID. One request.
func (c *Client) Project(ctx context.Context, cred Credential, uuid string) (Project, error) {
	var p Project
	_, err := c.get(ctx, cred, "v1/project/"+url.PathEscape(uuid), nil, &p)
	return p, err
}

// ProjectMetrics returns the current metrics of one project. One request.
func (c *Client) ProjectMetrics(ctx context.Context, cred Credential, uuid string) (Metrics, error) {
	var m Metrics
	_, err := c.get(ctx, cred, "v1/metrics/project/"+url.PathEscape(uuid)+"/current", nil, &m)
	return m, err
}

// PortfolioMetrics returns the current metrics of the whole portfolio, which
// Dependency-Track precomputes. One request.
func (c *Client) PortfolioMetrics(ctx context.Context, cred Credential) (Metrics, error) {
	var m Metrics
	_, err := c.get(ctx, cred, "v1/metrics/portfolio/current", nil, &m)
	return m, err
}

// ProjectFindings returns the findings of one project. At most
// MaxFindingPages requests; Page.Complete says whether that was all of them.
func (c *Client) ProjectFindings(ctx context.Context, cred Credential, uuid string, includeSuppressed bool) (Page[Finding], error) {
	q := url.Values{}
	q.Set("suppressed", strconv.FormatBool(includeSuppressed))
	return list[Finding](ctx, c, cred, "v1/finding/project/"+url.PathEscape(uuid), q, PageSize, MaxFindingPages)
}

// ProjectViolations returns policy violations of one project, up to limit.
// One request.
func (c *Client) ProjectViolations(ctx context.Context, cred Credential, uuid string, includeSuppressed bool, limit int) (Page[PolicyViolation], error) {
	q := url.Values{}
	q.Set("suppressed", strconv.FormatBool(includeSuppressed))
	return list[PolicyViolation](ctx, c, cred, "v1/violation/project/"+url.PathEscape(uuid), q, limit, 1)
}

// Vulnerability returns one vulnerability record. One request.
func (c *Client) Vulnerability(ctx context.Context, cred Credential, source, vulnID string) (Vulnerability, error) {
	var v Vulnerability
	_, err := c.get(ctx, cred, vulnPath(source, vulnID), nil, &v)
	return v, err
}

// AffectedProjects returns projects that carry a vulnerability, up to limit.
// One request.
func (c *Client) AffectedProjects(ctx context.Context, cred Credential, source, vulnID string, includeInactive bool, limit int) (Page[AffectedProject], error) {
	q := url.Values{}
	if !includeInactive {
		q.Set("excludeInactive", "true")
	}
	return list[AffectedProject](ctx, c, cred, vulnPath(source, vulnID)+"/projects", q, limit, 1)
}

func vulnPath(source, vulnID string) string {
	return "v1/vulnerability/source/" + url.PathEscape(source) + "/vuln/" + url.PathEscape(vulnID)
}

// SourceForID guesses the Dependency-Track source of a vulnerability from
// the shape of its ID. It returns "" when the ID gives no hint.
func SourceForID(vulnID string) string {
	id := strings.ToUpper(vulnID)
	switch {
	case strings.HasPrefix(id, "CVE-"):
		return "NVD"
	case strings.HasPrefix(id, "GHSA-"):
		return "GITHUB"
	case strings.HasPrefix(id, "SNYK-"):
		return "SNYK"
	case strings.HasPrefix(id, "SONATYPE-"):
		return "OSSINDEX"
	case strings.HasPrefix(id, "GO-"), strings.HasPrefix(id, "PYSEC-"), strings.HasPrefix(id, "RUSTSEC-"),
		strings.HasPrefix(id, "OSV-"), strings.HasPrefix(id, "MAL-"):
		return "OSV"
	}
	return ""
}
