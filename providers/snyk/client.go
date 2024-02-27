package snyk

import (
	"fmt"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const userAgent = "Bomber"

func newClient(c *models.Credentials) *HttpRequest.Request {
	return HttpRequest.NewRequest().SetHeaders(map[string]string{
		"Authorization": fmt.Sprintf("token %s", c.ProviderToken),
		"User-Agent":    userAgent,
	})
}
