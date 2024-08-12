package ossindex

import (
	"os"
	"testing"

	"github.com/jarcoal/httpmock"
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

	err := validateCredentials(nil)
	assert.Error(t, err)

	username := os.Getenv("BOMBER_PROVIDER_USERNAME")
	token := os.Getenv("BOMBER_PROVIDER_TOKEN")

	os.Unsetenv("BOMBER_PROVIDER_USERNAME")
	os.Unsetenv("BOMBER_PROVIDER_TOKEN")
	credentials := models.Credentials{
		Username:      "test",
		ProviderToken: "token",
	}

	err = validateCredentials(&credentials)
	assert.NoError(t, err)

	credentials.Username = ""
	credentials.ProviderToken = ""
	err = validateCredentials(&credentials)
	assert.Error(t, err)

	os.Setenv("BOMBER_PROVIDER_USERNAME", "test-env")
	os.Setenv("BOMBER_PROVIDER_TOKEN", "token-env")

	err = validateCredentials(&credentials)
	assert.NoError(t, err)
	assert.Equal(t, "test-env", credentials.Username)
	assert.Equal(t, "token-env", credentials.ProviderToken)

	//reset env
	os.Setenv("BOMBER_PROVIDER_USERNAME", username)
	os.Setenv("BOMBER_PROVIDER_TOKEN", token)
}

func TestProvider_Scan(t *testing.T) {

	credentials := models.Credentials{
	//	Username:      os.Getenv("BOMBER_PROVIDER_USERNAME"),
	//	ProviderToken: os.Getenv("BOMBER_PROVIDER_TOKEN"),
	}

	httpmock.ActivateNonDefault(client.GetClient())
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", ossindexURL,
		httpmock.NewBytesResponder(200, ossTestResponse()))

	provider := Provider{}

	packages, err := provider.Scan([]string{"pkg:golang/github.com/briandowns/spinner@v1.19.0"}, &credentials)
	assert.NoError(t, err)
	assert.Equal(t, "pkg:gem/tzinfo@1.2.5", packages[0].Purl)
	assert.Len(t, packages[0].Vulnerabilities, 1)

	_, e := provider.Scan([]string{"pkg:golang/github.com/briandowns/spinner@v1.19.0"}, nil)
	assert.Error(t, e)

	httpmock.GetTotalCallCount()
}

func TestProvider_Scan_FakeCredentials(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("POST", ossindexURL,
		httpmock.NewBytesResponder(200, ossTestResponse()))

	credentials := models.Credentials{
		Username:      "test",
		ProviderToken: "token",
	}

	provider := Provider{}
	_, err := provider.Scan([]string{"pkg:golang/github.com/briandowns/spinner@v1.19.0"}, &credentials)
	assert.Error(t, err)
}

func ossTestResponse() []byte {
	response := `
	[
		{
			"coordinates": "pkg:gem/tzinfo@1.2.5",
			"description": "TZInfo provides daylight savings aware transformations between times in different time zones.",
			"reference": "https://ossindex.sonatype.org/component/pkg:gem/tzinfo@1.2.5?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
			"vulnerabilities": [
			{
				"id": "CVE-2022-31163",
				"displayName": "CVE-2022-31163",
				"title": "[CVE-2022-31163] CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
				"description": "TZInfo... ",
				"cvssScore": 8.1,
				"cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
				"cwe": "CWE-22",
				"cve": "CVE-2022-31163",
				"reference": "https://ossindex.sonatype.org/vulnerability/CVE-2022-31163?component-type=gem&component-name=tzinfo&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
				"externalReferences": [
					"http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-31163",
					"https://github.com/tzinfo/tzinfo/releases/tag/v0.3.61",
					"https://github.com/tzinfo/tzinfo/releases/tag/v1.2.10",
					"https://github.com/tzinfo/tzinfo/security/advisories/GHSA-5cm2-9h8c-rvfx"
				]
			}
			]
		}
	]`
	return []byte(response)
}
