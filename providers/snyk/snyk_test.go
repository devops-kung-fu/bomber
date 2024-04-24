package snyk

import (
	_ "embed"
)

// //go:embed testdata/snyk_package_issues_response.json
// var issuesResponse []byte

// //go:embed testdata/snyk_self_response.json
// var selfResponse []byte

// func TestInfo(t *testing.T) {
// 	provider := Provider{}
// 	info := provider.Info()
// 	assert.Equal(t, "Snyk (https://security.snyk.io)", info)
// }

// func Test_validateCredentials(t *testing.T) {
// 	// Back up any env tokens
// 	bomberToken := os.Getenv("BOMBER_PROVIDER_TOKEN")
// 	snykToken := os.Getenv("SNYK_TOKEN")

// 	os.Unsetenv("BOMBER_PROVIDER_TOKEN")
// 	os.Unsetenv("SNYK_TOKEN")

// 	credentials := models.Credentials{
// 		ProviderToken: "token",
// 	}

// 	err := validateCredentials(nil)
// 	assert.Error(t, err)

// 	err = validateCredentials(&credentials)
// 	assert.NoError(t, err)

// 	credentials.ProviderToken = ""
// 	err = validateCredentials(&credentials)
// 	assert.Error(t, err)

// 	os.Setenv("BOMBER_PROVIDER_TOKEN", "bomber-token")

// 	err = validateCredentials(&credentials)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "bomber-token", credentials.ProviderToken)

// 	os.Setenv("SNYK_TOKEN", "snyk-token")

// 	credentials.ProviderToken = ""
// 	err = validateCredentials(&credentials)
// 	assert.NoError(t, err)
// 	assert.Equal(t, "snyk-token", credentials.ProviderToken)

// 	//reset env
// 	os.Setenv("BOMBER_PROVIDER_TOKEN", bomberToken)
// 	os.Setenv("SNYK_TOKEN", snykToken)
// }

// func TestProvider_Scan_FakeCredentials(t *testing.T) {
// 	httpmock.Activate()
// 	defer httpmock.DeactivateAndReset()

// 	httpmock.RegisterResponder("GET", `=~\/self`, httpmock.NewBytesResponder(200, selfResponse))
// 	httpmock.RegisterResponder("GET", `=~\/issues`, httpmock.NewBytesResponder(200, issuesResponse))

// 	credentials := models.Credentials{
// 		ProviderToken: "token",
// 	}

// 	provider := Provider{}
// 	_, err := provider.Scan([]string{"pkg:gem/tzinfo@1.2.5"}, &credentials)
// 	assert.Error(t, err)

// }
