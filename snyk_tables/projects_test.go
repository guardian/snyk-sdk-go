package snyk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestProject_List(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/org/long-uuid/projects", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = fmt.Fprint(w, `
{
  "org": {
    "id": "long-uuid",
    "name": "test-org"
  },
  "projects": [
    {
      "id": "e8feca4a-4ebc-494f-80d9-f8b0532188da",
      "name": "test-org/test-project",
      "origin": "github",
			"issueCountsBySeverity": {
        "low": 8,
        "medium": 15,
        "high": 10,
        "critical": 3
      },
			"tags": [
        {
          "key": "example-tag-key",
          "value": "example-tag-value"
        }
      ]
    }
  ]
}
`)
	})
	expectedProjects := []Project{
		{
			ID:     "e8feca4a-4ebc-494f-80d9-f8b0532188da",
			Name:   "test-org/test-project",
			Origin: "github",
			IssueCountsBySeverity: map[string]int{
				"low":      8,
				"medium":   15,
				"high":     10,
				"critical": 3,
			},
			Tags: []Tag{
				{Key: "example-tag-key",
					Value: "example-tag-value",
				},
			},
		},
	}

	actualProjects, _, err := client.Projects.List(ctx, "long-uuid")

	assert.NoError(t, err)
	assert.Equal(t, expectedProjects, actualProjects)
}

func TestProject_List_emptyOrganizationID(t *testing.T) {
	setup()
	defer teardown()

	_, _, err := client.Projects.List(ctx, "")

	assert.Error(t, err)
	assert.Equal(t, ErrEmptyArgument, err)
}
