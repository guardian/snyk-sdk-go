package snyk

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"time"
)

const orgBasePath = "org"

// OrgsService handles communication with the organization related methods of the Snyk API.
type OrgsService service

// Organization represents a Snyk organization.
type Organization struct {
	Group *Group `json:"group,omitempty"`
	ID    string `json:"id,omitempty"`
	Name  string `json:"name,omitempty"`
	Slug  string `json:"slug,omitempty"`
	URL   string `json:"url,omitempty"`
}

// Group represents a Snyk group.
type Group struct {
	ID   string `json:"id,omitempty"`
	Name string `json:"name,omitempty"`
}

// OrganizationCreateRequest represents a request to create an organization.
type OrganizationCreateRequest struct {
	Name        string `json:"name,omitempty"`
	GroupID     string `json:"groupId,omitempty"`
	SourceOrgID string `json:"sourceOrgId,omitempty"` // id of the organization to copy settings from.
}

type organizationsRoot struct {
	Organizations []Organization `json:"orgs,omitempty"`
}

// List provides a list of all organizations a user belongs to.
func (s *OrgsService) List(ctx context.Context) ([]Organization, *Response, error) {
	req, err := s.client.NewRequest(http.MethodGet, "orgs", nil)
	if err != nil {
		return nil, nil, err
	}

	root := new(organizationsRoot)
	resp, err := s.client.Do(ctx, req, root)
	if err != nil {
		return nil, resp, err
	}

	return root.Organizations, resp, nil
}

// Create makes a new organization with given payload.
//
// If the [OrganizationCreateRequest.groupID] is not provided, a personal
// organization will be created independent of a group.
func (s *OrgsService) Create(ctx context.Context, createRequest *OrganizationCreateRequest) (*Organization, *Response, error) {
	if createRequest == nil {
		return nil, nil, ErrEmptyPayloadNotAllowed
	}

	req, err := s.client.NewRequest(http.MethodPost, orgBasePath, createRequest)
	if err != nil {
		return nil, nil, err
	}

	org := new(Organization)
	resp, err := s.client.Do(ctx, req, org)
	if err != nil {
		return nil, resp, err
	}

	return org, resp, nil
}

// Delete removes an organization identified by id.
func (s *OrgsService) Delete(ctx context.Context, organizationID string) (*Response, error) {
	if organizationID == "" {
		return nil, ErrEmptyArgument
	}

	path := fmt.Sprintf("%v/%v", orgBasePath, organizationID)

	req, err := s.client.NewRequest(http.MethodDelete, path, nil)
	if err != nil {
		return nil, err
	}

	return s.client.Do(ctx, req, nil)
}

// OrganizationMember is the same as User, but includes a Role and doesn't include a list of organizations.
type OrganizationMember struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Name     string `json:"name"`
	Email    string `json:"email"`
	Role     string `json:"role"`
}

// ListMembers provides a list of all members in an organization.
func (s *OrgsService) ListMembers(ctx context.Context, orgID string, includeGroupAdmins bool) ([]OrganizationMember, *Response, error) {
	urlStr := fmt.Sprintf("org/%s/members", orgID)
	if includeGroupAdmins {
		urlStr += "?includeGroupAdmins=true"
	}
	req, err := s.client.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, nil, err
	}

	var members []OrganizationMember
	resp, err := s.client.Do(ctx, req, &members)
	if err != nil {
		return nil, resp, err
	}

	return members, resp, nil
}

type PendingProvision struct {
	Email        string     `json:"email"`
	Role         string     `json:"role"`
	RolePublicID string     `json:"rolePublicId"`
	Created      *time.Time `json:"created"`
}

type ListPendingUserProvisionsOptions struct {
	PerPage int
	Page    int
}

// ListPendingUserProvisions provides a list of all pending user provisions in an organization.
func (s *OrgsService) ListPendingUserProvisions(ctx context.Context, orgID string, opts ListPendingUserProvisionsOptions) ([]PendingProvision, *Response, error) {
	urlStr := fmt.Sprintf("org/%s/provision?", orgID)
	vals := url.Values{}
	if opts.PerPage > 0 {
		vals["perPage"] = []string{strconv.Itoa(opts.PerPage)}
	}
	if opts.Page > 0 {
		vals["page"] = []string{strconv.Itoa(opts.Page)}
	}
	urlStr += vals.Encode()
	req, err := s.client.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, nil, err
	}

	var provisions []PendingProvision
	resp, err := s.client.Do(ctx, req, &provisions)
	if err != nil {
		return nil, resp, err
	}

	return provisions, resp, nil
}
