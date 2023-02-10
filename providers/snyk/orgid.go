package snyk

import (
	"encoding/json"
	"fmt"

	"github.com/kirinlabs/HttpRequest"
)

type selfDocument struct {
	Data struct {
		Attributes struct {
			AvatarURL         string `json:"avatar_url,omitempty"`
			DefaultOrgContext string `json:"default_org_context,omitempty"`
			Name              string `json:"name,omitempty"`
			Username          string `json:"username,omitempty"`
		} `json:"attributes,omitempty"`
		ID   string `json:"id,omitempty"`
		Type string `json:"type,omitempty"`
	}
	Jsonapi JSONAPI        `json:"jsonapi,omitempty"`
	Links   PaginatedLinks `json:"links,omitempty"`
}

func getOrgID(client *HttpRequest.Request) (orgID string, err error) {
	res, err := client.Get(SnykURL + "/self" + SnykAPIVersion)
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}

	body, err := res.Body()
	if err != nil {
		return "", fmt.Errorf("unable to retrieve org ID: %w", err)
	}

	if res.StatusCode() != 200 {
		return "", fmt.Errorf("unable to retrieve org ID (status: %s)", res.Response().Status)
	}

	var userInfo selfDocument
	if err = json.Unmarshal(body, &userInfo); err != nil {
		return "", fmt.Errorf("unable to retrieve org ID (status: %s): %w", res.Response().Status, err)
	}

	orgID = userInfo.Data.Attributes.DefaultOrgContext

	return
}
