package ossindex

import (
	"os"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestInfo(t *testing.T) {
	provider := Provider{}
	info := provider.Info()
	assert.Equal(t, "Sonatype OSS Index (https://ossindex.sonatype.org)", info)
}

func Test_validateCredentials(t *testing.T) {
	// Back up any env tokens

	username := os.Getenv("BOMBER_PROVIDER_USERNAME")
	token := os.Getenv("BOMBER_PROVIDER_TOKEN")

	os.Unsetenv("BOMBER_PROVIDER_USERNAME")
	os.Unsetenv("BOMBER_PROVIDER_TOKEN")
	credentials := models.Credentials{
		Username: "test",
		Token:    "token",
	}

	err := validateCredentials(&credentials)
	assert.NoError(t, err)

	credentials.Username = ""
	credentials.Token = ""
	err = validateCredentials(&credentials)
	assert.Error(t, err)

	os.Setenv("BOMBER_PROVIDER_USERNAME", "test-env")
	os.Setenv("BOMBER_PROVIDER_TOKEN", "token-env")

	err = validateCredentials(&credentials)
	assert.NoError(t, err)
	assert.Equal(t, "test-env", credentials.Username)
	assert.Equal(t, "token-env", credentials.Token)

	//reset env
	os.Setenv("BOMBER_PROVIDER_USERNAME", username)
	os.Setenv("BOMBER_PROVIDER_TOKEN", token)
}
