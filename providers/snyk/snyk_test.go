package snyk

import (
	_ "embed"
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

//go:embed testdata/snyk_package_issues_response.json
var issuesResponse []byte

//go:embed testdata/snyk_self_response.json
var selfResponse []byte

func TestInfo(t *testing.T) {
	provider := Provider{}
	info := provider.Info()
	assert.Equal(t, "Snyk (https://security.snyk.io)", info)
}

func Test_validateCredentials(t *testing.T) {
	// Back up any env tokens
	bomberToken := os.Getenv("BOMBER_PROVIDER_TOKEN")
	snykToken := os.Getenv("SNYK_TOKEN")

	os.Unsetenv("BOMBER_PROVIDER_TOKEN")
	os.Unsetenv("SNYK_TOKEN")

	credentials := models.Credentials{
		Token: "token",
	}

	err := validateCredentials(nil)
	assert.Error(t, err)

	err = validateCredentials(&credentials)
	assert.NoError(t, err)

	credentials.Token = ""
	err = validateCredentials(&credentials)
	assert.Error(t, err)

	os.Setenv("BOMBER_PROVIDER_TOKEN", "bomber-token")

	err = validateCredentials(&credentials)
	assert.NoError(t, err)
	assert.Equal(t, "bomber-token", credentials.Token)

	os.Setenv("SNYK_TOKEN", "snyk-token")

	credentials.Token = ""
	err = validateCredentials(&credentials)
	assert.NoError(t, err)
	assert.Equal(t, "snyk-token", credentials.Token)

	//reset env
	os.Setenv("BOMBER_PROVIDER_TOKEN", bomberToken)
	os.Setenv("SNYK_TOKEN", snykToken)
}

func TestProvider_Scan_FakeCredentials(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~\/self`, httpmock.NewBytesResponder(200, selfResponse))
	httpmock.RegisterResponder("GET", `=~\/issues`, httpmock.NewBytesResponder(200, issuesResponse))

	credentials := models.Credentials{
		Token: "token",
	}

	provider := Provider{}
	pkgs, err := provider.Scan([]string{"pkg:gem/tzinfo@1.2.5"}, &credentials)
	assert.NoError(t, err)
	assert.Len(t, pkgs, 1)
	pkg := pkgs[0]
	assert.Equal(t, "pkg:gem/tzinfo@1.2.5", pkg.Purl)
	assert.Len(t, pkg.Vulnerabilities, 1)
	httpmock.GetTotalCallCount()
	calls := httpmock.GetCallCountInfo()
	assert.Equal(t, 1, calls[`GET =~\/self`])
	assert.Equal(t, 1, calls[`GET =~\/issues`])
}
