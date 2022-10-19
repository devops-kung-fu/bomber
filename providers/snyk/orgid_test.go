package snyk

import (
	"net/http"
	"testing"

	"github.com/devops-kung-fu/bomber/models"
	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"
)

func TestGetOrgID(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(http.MethodGet, `=~\/self`, httpmock.NewBytesResponder(200, selfResponse))

	client := newClient(&models.Credentials{})
	orgID, err := getOrgID(client)

	assert.NoError(t, err)
	assert.Equal(t, "d9546f87-d03d-4dd9-a10e-6ae5fd40d9a1", orgID)
}

func TestGetOrgIDUnauthorized(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(http.MethodGet, `=~\/self`, httpmock.NewStringResponder(401, "Unauthorized"))

	client := newClient(&models.Credentials{})
	orgID, err := getOrgID(client)

	assert.Error(t, err)
	assert.Equal(t, "unable to retrieve org ID (status: 401)", err.Error())
	assert.Equal(t, "", orgID)
}

func TestGetOrgIDInvalidResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder(http.MethodGet, `=~\/self`, httpmock.NewStringResponder(200, "boom"))

	client := newClient(&models.Credentials{})
	orgID, err := getOrgID(client)

	assert.Error(t, err)
	assert.Equal(t, "unable to retrieve org ID (status: 200): invalid character 'b' looking for beginning of value", err.Error())
	assert.Equal(t, "", orgID)
}
