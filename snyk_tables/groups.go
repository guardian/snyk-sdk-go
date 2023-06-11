package snyk

import (
	"context"
	"fmt"
	"net/http"
)

// GroupsService handles communication with the group related methods of the Snyk API.
type GroupsService service

type GroupMember struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Username string `json:"username"`
	Email    string `json:"email"`
	Orgs     []struct {
		Name string `json:"name"`
		Role string `json:"role"`
	} `json:"orgs"`
	GroupRole string `json:"groupRole"`
}

// ListMembers provides a list of all members in a group.
func (s *GroupsService) ListMembers(ctx context.Context, groupID string) ([]GroupMember, *Response, error) {
	urlStr := fmt.Sprintf("group/%s/members", groupID)
	req, err := s.client.NewRequest(http.MethodGet, urlStr, nil)
	if err != nil {
		return nil, nil, err
	}

	var members []GroupMember
	resp, err := s.client.Do(ctx, req, &members)
	if err != nil {
		return nil, resp, err
	}

	return members, resp, nil
}
