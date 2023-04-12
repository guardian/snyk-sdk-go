package snyk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestReporting_ListLatestIssues(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/v1/reporting/issues/latest", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = fmt.Fprint(w, `
{
  "results": [
    {
      "issue": {
        "url": "",
        "id": "e8feca4a-4ebc-494f-80d9-f8b0532188da",
        "title": "",
        "type": "",
        "package": "",
        "version": "",
        "severity": "",
        "originalSeverity": "",
        "uniqueSeveritiesList": [],
        "exploitMaturity": "",
        "isUpgradable": false,
        "isPatchable": false,
        "isPinnable": false,
        "jiraIssueUrl": "",
        "publicationTime": "",
        "disclosureTime": "",
        "language": "",
        "packageManager": "",
        "identifiers": {
          "CVE": [],
          "CWE": [],
          "OSVDB": []
        },
        "credit": [],
        "CVSSv3": "",
        "priorityScore": 0,
        "cvssScore": 0,
        "patches": [
          {
            "id": "",
            "urls": [],
            "version": "",
            "comments": [],
            "modificationTime": ""
          }
        ],
        "isIgnored": false,
        "isPatched": false,
        "semver": {
          "vulnerable": [],
          "unaffected": ""
        },
        "ignored": [
          {
            "reason": "",
            "expires": "",
            "source": "cli"
          }
        ]
      },
      "projects": [
        {
          "url": "",
          "id": "",
          "name": "",
          "source": "",
          "packageManager": "",
          "targetFile": ""
        }
      ],
      "isFixed": false,
      "introducedDate": "",
      "patchedDate": "",
      "fixedDate": ""
    }
  ],
  "total": 0
}
`)
	})
	expectedID := "e8feca4a-4ebc-494f-80d9-f8b0532188da"

	req := ListReportingIssuesRequest{}
	response, _, err := client.Reporting.ListLatestIssues(ctx, "test-id", req)
	if err != nil {
		t.Fatalf("expected no error, got %s", err)
	}
	if len(response.Results) != 1 {
		t.Fatalf("expected one result, got %d", len(response.Results))
	}
	gotID := response.Results[0].Issue.ID
	assert.NoError(t, err)
	assert.Equal(t, expectedID, gotID)
}
