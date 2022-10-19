package snyk

import (
	"fmt"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const USER_AGENT = "Bomber"

func newClient(c *models.Credentials) *HttpRequest.Request {
	return HttpRequest.NewRequest().SetHeaders(map[string]string{
		"Authorization": fmt.Sprintf("token %s", c.Token),
		"User-Agent":    USER_AGENT,
	})
}
