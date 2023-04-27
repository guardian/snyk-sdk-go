package snyk

import (
	"encoding/json"
	"fmt"
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
)

func TestOrgs_List(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/orgs", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = fmt.Fprint(w, `
{
  "orgs": [
    {
      "id": "long-uuid-first",
      "name": "Test Org First"
    },
    {
      "id": "long-uuid-second",
      "slug": "test-org-second",
      "url": "https://testing.snyk.io/api/org/test-org-second",
      "group": null
    }
  ]
}
`)
	})
	expectedOrgs := []Organization{
		{
			ID:   "long-uuid-first",
			Name: "Test Org First",
		},
		{
			ID:   "long-uuid-second",
			Slug: "test-org-second",
			URL:  "https://testing.snyk.io/api/org/test-org-second",
		},
	}

	actualOrgs, _, err := client.Orgs.List(ctx)

	assert.NoError(t, err)
	assert.Equal(t, expectedOrgs, actualOrgs)
}

func TestOrgs_Create(t *testing.T) {
	setup()
	defer teardown()

	input := &OrganizationCreateRequest{
		Name: "Test Org",
	}
	mux.HandleFunc("/org", func(w http.ResponseWriter, r *http.Request) {
		v := new(OrganizationCreateRequest)
		_ = json.NewDecoder(r.Body).Decode(v)
		assert.Equal(t, input, v)
		assert.Equal(t, http.MethodPost, r.Method)
		_, _ = fmt.Fprint(w, `
{
  "id": "long-uuid",
  "name": "Test Org",
  "slug": "test-org",
  "url": "https://testing.snyk.io/api/org/test-org",
  "group": null
}
`)
	})
	expectedOrg := &Organization{
		ID:   "long-uuid",
		Name: "Test Org",
		Slug: "test-org",
		URL:  "https://testing.snyk.io/api/org/test-org",
	}

	actualOrg, _, err := client.Orgs.Create(ctx, input)

	assert.NoError(t, err)
	assert.Equal(t, expectedOrg, actualOrg)
}

func TestOrgs_Create_emptyPayload(t *testing.T) {
	setup()
	defer teardown()

	_, _, err := client.Orgs.Create(ctx, nil)

	assert.Error(t, err)
	assert.Equal(t, ErrEmptyPayloadNotAllowed, err)
}

func TestOrgs_Delete(t *testing.T) {
	setup()
	defer teardown()

	mux.HandleFunc("/org/long-uuid", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodDelete, r.Method)
	})

	_, err := client.Orgs.Delete(ctx, "long-uuid")

	assert.NoError(t, err)
}

func TestOrgs_Delete_emptyOrganizationID(t *testing.T) {
	setup()
	defer teardown()

	_, err := client.Orgs.Delete(ctx, "")

	assert.Error(t, err)
	assert.Equal(t, ErrEmptyArgument, err)
}

func TestOrgs_ListMembers(t *testing.T) {
	setup()
	defer teardown()

	orgID := "test-org"
	mux.HandleFunc("/org/"+orgID+"/members", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = fmt.Fprint(w, `
[
  {
    "id": "test-id",
    "name": "test-name",
    "username": "test-username",
    "email": "test-email",
    "role": "test-role"
  }
]
`)
	})
	expectedMembers := []OrganizationMember{
		{
			ID:       "test-id",
			Name:     "test-name",
			Username: "test-username",
			Email:    "test-email",
			Role:     "test-role",
		},
	}

	actualMembers, _, err := client.Orgs.ListMembers(ctx, orgID, true)

	assert.NoError(t, err)
	assert.Equal(t, expectedMembers, actualMembers)
}

func TestOrgs_ListPendingUserProvisions(t *testing.T) {
	setup()
	defer teardown()

	orgID := "test-org"
	mux.HandleFunc("/org/"+orgID+"/provision", func(w http.ResponseWriter, r *http.Request) {
		assert.Equal(t, http.MethodGet, r.Method)
		_, _ = fmt.Fprint(w, `
[
  {
    "email": "test-email",
    "role": "test-role",
    "rolePublicId": "test-role-public-id",
    "created": "2019-02-04T06:19:00.000Z"
  }
]
`)
	})
	created := time.Date(2019, 2, 4, 6, 19, 0, 0, time.UTC)
	expectedProvisions := []PendingProvision{
		{
			Email:        "test-email",
			Role:         "test-role",
			RolePublicID: "test-role-public-id",
			Created:      &created,
		},
	}

	actualProvisions, _, err := client.Orgs.ListPendingUserProvisions(ctx, orgID, ListPendingUserProvisionsOptions{})

	assert.NoError(t, err)
	assert.Equal(t, expectedProvisions, actualProvisions)
}
