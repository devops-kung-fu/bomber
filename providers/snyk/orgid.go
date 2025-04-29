package snyk

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"

	"github.com/go-resty/resty/v2"
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

func getOrgID(token string) (orgID string, err error) {
	client := resty.New()
	client.Debug = true

	resp, err := client.R().
		SetHeader("User-Agent", "bomber").
		SetAuthScheme("token").
		SetAuthToken(token).
		Get(getSnykAPIURL() + "/rest/self" + SnykAPIVersion)

	if err != nil {
		log.Print(err)
		return "", err
	}

	if resp.StatusCode() == http.StatusOK {
		var userInfo selfDocument
		if err = json.Unmarshal(resp.Body(), &userInfo); err != nil {
			return "", fmt.Errorf("unable to retrieve org ID (status: %x): %w", resp.StatusCode(), err)
		}

		orgID = userInfo.Data.Attributes.DefaultOrgContext

		return orgID, nil
	} else {
		log.Println("Error: unexpected status code", resp.StatusCode())
		return "", fmt.Errorf("unable to retrieve org ID (status: %x)", resp.StatusCode())
	}
}
