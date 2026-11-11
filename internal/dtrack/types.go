package dtrack

import (
	"bytes"
	"encoding/json"
	"sort"
	"strings"
	"time"
)

// Time decodes the timestamps Dependency-Track sends, which are epoch
// milliseconds on some fields and RFC 3339 strings on others.
type Time struct{ time.Time }

// UnmarshalJSON accepts a number (epoch milliseconds), a string or null.
func (t *Time) UnmarshalJSON(b []byte) error {
	b = bytes.TrimSpace(b)
	if len(b) == 0 || bytes.Equal(b, []byte("null")) {
		return nil
	}
	if b[0] == '"' {
		var s string
		if err := json.Unmarshal(b, &s); err != nil {
			return err
		}
		for _, layout := range []string{time.RFC3339, "2006-01-02T15:04:05.000Z0700", "2006-01-02"} {
			if parsed, err := time.Parse(layout, s); err == nil {
				t.Time = parsed.UTC()
				return nil
			}
		}
		return nil // unknown format: leave zero rather than fail the call
	}
	var ms float64
	if err := json.Unmarshal(b, &ms); err != nil {
		return nil
	}
	t.Time = time.UnixMilli(int64(ms)).UTC()
	return nil
}

// String returns the time as RFC 3339, or "" when unset.
func (t Time) String() string {
	if t.IsZero() {
		return ""
	}
	return t.Format(time.RFC3339)
}

// Tag is a project tag.
type Tag struct {
	Name string `json:"name"`
}

// Metrics are the counts Dependency-Track keeps per project and for the
// portfolio. Portfolio-only fields are zero on a project.
type Metrics struct {
	Critical             int     `json:"critical"`
	High                 int     `json:"high"`
	Medium               int     `json:"medium"`
	Low                  int     `json:"low"`
	Unassigned           int     `json:"unassigned"`
	Vulnerabilities      int     `json:"vulnerabilities"`
	Projects             int     `json:"projects"`
	VulnerableProjects   int     `json:"vulnerableProjects"`
	Components           int     `json:"components"`
	VulnerableComponents int     `json:"vulnerableComponents"`
	Suppressed           int     `json:"suppressed"`
	FindingsTotal        int     `json:"findingsTotal"`
	FindingsAudited      int     `json:"findingsAudited"`
	FindingsUnaudited    int     `json:"findingsUnaudited"`
	InheritedRiskScore   float64 `json:"inheritedRiskScore"`
	PolicyViolationsFail int     `json:"policyViolationsFail"`
	PolicyViolationsWarn int     `json:"policyViolationsWarn"`
	PolicyViolationsInfo int     `json:"policyViolationsInfo"`
	LastOccurrence       Time    `json:"lastOccurrence"`
}

// Project is a Dependency-Track project (one name and version).
type Project struct {
	UUID          string   `json:"uuid"`
	Name          string   `json:"name"`
	Version       string   `json:"version"`
	Classifier    string   `json:"classifier"`
	Active        *bool    `json:"active"`
	IsLatest      bool     `json:"isLatest"`
	Tags          []Tag    `json:"tags"`
	Metrics       *Metrics `json:"metrics"`
	LastBomImport Time     `json:"lastBomImport"`
}

// IsActive reports whether the project is active. A missing field means
// active, which is how older versions serialize it.
func (p Project) IsActive() bool { return p.Active == nil || *p.Active }

// TagNames returns the project's tag names, sorted.
func (p Project) TagNames() []string {
	names := make([]string, 0, len(p.Tags))
	for _, t := range p.Tags {
		names = append(names, t.Name)
	}
	sort.Strings(names)
	return names
}

// CWE is a weakness a vulnerability is classified under.
type CWE struct {
	ID   int    `json:"cweId"`
	Name string `json:"name"`
}

// Vulnerability is the part of a vulnerability record the tools report.
type Vulnerability struct {
	VulnID         string           `json:"vulnId"`
	Source         string           `json:"source"`
	Title          string           `json:"title"`
	Description    string           `json:"description"`
	Severity       string           `json:"severity"`
	CVSSv4         *float64         `json:"cvssV4Score"`
	CVSSv3         *float64         `json:"cvssV3BaseScore"`
	CVSSv2         *float64         `json:"cvssV2BaseScore"`
	EPSSScore      *float64         `json:"epssScore"`
	EPSSPercentile *float64         `json:"epssPercentile"`
	IsKEV          bool             `json:"isKev"`
	CWEs           []CWE            `json:"cwes"`
	Aliases        []map[string]any `json:"aliases"`
	Published      Time             `json:"published"`
}

// CVSS returns the newest CVSS base score the record carries, or nil.
func (v Vulnerability) CVSS() *float64 {
	for _, score := range []*float64{v.CVSSv4, v.CVSSv3, v.CVSSv2} {
		if score != nil {
			return score
		}
	}
	return nil
}

// AliasIDs returns the other identifiers of this vulnerability (for example
// the GHSA of a CVE), sorted, without the record's own ID.
func (v Vulnerability) AliasIDs() []string {
	seen := map[string]bool{v.VulnID: true}
	ids := []string{}
	for _, alias := range v.Aliases {
		for key, value := range alias {
			id, ok := value.(string)
			if !ok || id == "" || !strings.HasSuffix(key, "Id") || seen[id] {
				continue
			}
			seen[id] = true
			ids = append(ids, id)
		}
	}
	sort.Strings(ids)
	return ids
}

// Finding is a vulnerability on a component of a project.
type Finding struct {
	Component struct {
		Name          string `json:"name"`
		Version       string `json:"version"`
		PURL          string `json:"purl"`
		LatestVersion string `json:"latestVersion"`
	} `json:"component"`
	Vulnerability Vulnerability `json:"vulnerability"`
	Analysis      struct {
		State        string `json:"state"`
		IsSuppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
}

// PolicyViolation is a policy condition a component of a project violates.
type PolicyViolation struct {
	Type      string `json:"type"`
	Timestamp Time   `json:"timestamp"`
	Component struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		PURL    string `json:"purl"`
	} `json:"component"`
	PolicyCondition struct {
		Operator string `json:"operator"`
		Subject  string `json:"subject"`
		Value    string `json:"value"`
		Policy   struct {
			Name           string `json:"name"`
			ViolationState string `json:"violationState"`
		} `json:"policy"`
	} `json:"policyCondition"`
	Analysis *struct {
		State        string `json:"analysisState"`
		IsSuppressed bool   `json:"isSuppressed"`
	} `json:"analysis"`
}

// AffectedProject is a project that carries a given vulnerability.
type AffectedProject struct {
	UUID    string `json:"uuid"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Active  *bool  `json:"active"`
}

// SeverityRank orders severities, most severe first. Unknown values sort
// last.
func SeverityRank(severity string) int {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return 0
	case "HIGH":
		return 1
	case "MEDIUM":
		return 2
	case "LOW":
		return 3
	case "INFO":
		return 4
	}
	return 5
}
