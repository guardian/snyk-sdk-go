package snyk

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
)

const reportingBasePath = "v1/reporting"

// ReportingService handles communication with the reporting related methods of the Snyk API.
type ReportingService service

// ListReportingIssuesResponse represents the response from the Snyk API when
// listing issues.
type ListReportingIssuesResponse struct {
	Results []ListReportingIssueResult `json:"results"`
	Total   int                        `json:"total"`
}

// ListReportingIssueResult represents a single issue in the response from the
// Snyk API.
type ListReportingIssueResult struct {
	Issue          ListReportingIssue          `json:"issue"`
	Projects       []ListReportingIssueProject `json:"projects"` // When groupBy is used
	Project        ListReportingIssueProject   `json:"project"`  // When groupBy is not used
	IsFixed        bool                        `json:"isFixed"`
	IntroducedDate string                      `json:"introducedDate"`
	PatchedDate    string                      `json:"patchedDate"`
	FixedDate      string                      `json:"fixedDate"`
}

// ListReportingIssue represents an issue in the response from the Snyk API.
type ListReportingIssue struct {
	URL                  string   `json:"url"`
	ID                   string   `json:"id"`
	Title                string   `json:"title"`
	Type                 string   `json:"type"`
	Package              string   `json:"package"`
	Version              string   `json:"version"`
	Severity             string   `json:"severity"`
	OriginalSeverity     string   `json:"originalSeverity"`
	UniqueSeveritiesList []string `json:"uniqueSeveritiesList"`
	ExploitMaturity      string   `json:"exploitMaturity"`
	IsUpgradable         bool     `json:"isUpgradable"`
	IsPatchable          bool     `json:"isPatchable"`
	IsPinnable           bool     `json:"isPinnable"`
	JiraIssueURL         string   `json:"jiraIssueUrl"`
	PublicationTime      string   `json:"publicationTime"`
	DisclosureTime       string   `json:"disclosureTime"`
	Language             string   `json:"language"`
	PackageManager       string   `json:"packageManager"`
	Identifiers          struct {
		CVE   []string `json:"CVE"`
		CWE   []string `json:"CWE"`
		OSVDB []string `json:"OSVDB"`
	}
	Credit        []string    `json:"credit"`
	CVSSv3        string      `json:"CVSSv3"`
	PriorityScore int         `json:"priorityScore"`
	CVSSScore     json.Number `json:"cvssScore"`
	Patches       []struct {
		ID               string   `json:"id"`
		ModificationTime string   `json:"modificationTime"`
		Urls             []string `json:"urls"`
		Comments         []string `json:"comments"`
		Version          string   `json:"version"`
	}
	IsIgnored bool `json:"isIgnored"`
	IsPatched bool `json:"isPatched"`
	Semver    struct {
		Vulnerable []string `json:"vulnerable"`
		Unaffected string   `json:"unaffected"`
	}
	Ignored []struct {
		Reason  string `json:"reason"`
		Expires string `json:"expires"`
		Source  string `json:"source"`
	} `json:"ignored"`
}

// ListReportingIssueProject represents a project in the response from the Snyk
// API.
type ListReportingIssueProject struct {
	URL            string `json:"url"`
	ID             string `json:"id"`
	Name           string `json:"name"`
	Source         string `json:"source"`
	PackageManager string `json:"packageManager"`
	TargetFile     string `json:"targetFile"`
}

// ListReportingIssuesRequest represents the request to the Snyk API when
// listing issues.
type ListReportingIssuesRequest struct {
	Page    int
	PerPage int    // max 1000
	SortBy  string // Possible values: severity, issueTitle, projectName, isFixed, isPatched, isIgnored, introducedDate, isUpgradable, isPatchable, priorityScore
	Order   string // example: "asc"
	GroupBy string // only allowed value is "issue"
}

// ListLatestIssues lists the latest issues.
func (s *ReportingService) ListLatestIssues(ctx context.Context, organizationID string, req ListReportingIssuesRequest) (*ListReportingIssuesResponse, *Response, error) {
	q := url.Values{}
	if req.Page != 0 {
		q.Set("page", fmt.Sprint(req.Page))
	}
	if req.PerPage != 0 {
		q.Set("perPage", fmt.Sprint(req.PerPage))
	}
	if req.GroupBy != "" {
		q.Set("groupBy", req.GroupBy)
	}
	if req.Order != "" {
		q.Set("order", req.Order)
	}
	if req.SortBy != "" {
		q.Set("sortBy", req.SortBy)
	}
	body := map[string]any{
		"filters": map[string]any{
			"orgs": []string{organizationID},
		},
	}
	cr, err := s.client.NewRequest("POST", reportingBasePath+"/issues/latest?"+q.Encode(), body)
	if err != nil {
		return nil, nil, err
	}
	issuesResp := new(ListReportingIssuesResponse)
	resp, err := s.client.Do(ctx, cr, issuesResp)
	if err != nil {
		return nil, resp, err
	}
	return issuesResp, resp, nil
}
