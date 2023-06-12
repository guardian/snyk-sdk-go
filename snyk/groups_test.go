package snyk

import (
	"fmt"
	"net/http"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestGroups_ListMembers(t *testing.T) {
	setup()
	defer teardown()

	groupID := "test-group"
	mux.HandleFunc("/group/"+groupID+"/members", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = fmt.Fprint(w, `
[
  {
    "id": "test-id",
    "name": "test-name",
    "email": "test-email",
    "username": "test-username",
    "orgs": null,
    "groupRole": "test-role"
  },
  {
    "id": "test-id",
    "name": "test-name",
    "email": "test-email",
    "username": "test-username",
    "orgs": [{"name": "test-org", "role": "test-role"}],
    "groupRole": "test-role"
  }
]
`)
	})
	expectedMembers := []GroupMember{
		{
			ID:        "test-id",
			Name:      "test-name",
			Username:  "test-username",
			Email:     "test-email",
			Orgs:      nil,
			GroupRole: "test-role",
		},
		{
			ID:       "test-id",
			Name:     "test-name",
			Username: "test-username",
			Email:    "test-email",
			Orgs: []struct {
				Name string `json:"name"`
				Role string `json:"role"`
			}{{Name: "test-org", Role: "test-role"}},
			GroupRole: "test-role",
		},
	}

	actualMembers, _, err := client.Groups.ListMembers(ctx, groupID)

	assert.NoError(t, err)
	assert.Equal(t, expectedMembers, actualMembers)
}
