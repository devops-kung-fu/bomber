package snyk

// func TestGetOrgID(t *testing.T) {
// 	httpmock.Activate()
// 	defer httpmock.DeactivateAndReset()

// 	httpmock.RegisterResponder(http.MethodGet, `=~\/self`, httpmock.NewBytesResponder(200, selfResponse))

// 	orgID, err := getOrgID(os.Getenv("SNYK_TOKEN"))

// 	assert.NoError(t, err)
// 	assert.NotNil(t, orgID)
// 	assert.Len(t, orgID, 36)
// }

// func TestGetOrgIDUnauthorized(t *testing.T) {
// 	httpmock.Activate()
// 	defer httpmock.DeactivateAndReset()

// 	httpmock.RegisterResponder(http.MethodGet, `=~\/self`, httpmock.NewStringResponder(401, "Unauthorized"))

// 	orgID, err := getOrgID("Yeah")

// 	assert.Error(t, err)
// 	assert.Equal(t, "unable to retrieve org ID (status: 401 Unauthorized)", err.Error())
// 	assert.Equal(t, "", orgID)
// }
