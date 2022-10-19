package snyk

import (
	"encoding/json"
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

const orgID string = "33e75b5e-3ebe-4d2e-8eba-17a24d20fc72"

func TestGetVulnsForPurlSuccess(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~\/issues\?version=`, httpmock.NewBytesResponder(200, issuesResponse))

	expected := []models.Vulnerability{
		{
			ID:         "SNYK-RUBY-TZINFO-2958048",
			Title:      "Directory Traversal",
			Severity:   "HIGH",
			CvssScore:  float64(7.5),
			CvssVector: "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
			Cwe:        "CWE-22",
			Reference:  "https://security.snyk.io/vuln/SNYK-RUBY-TZINFO-2958048",
			ExternalReferences: []interface{}{
				"https://github.com/tzinfo/tzinfo/releases/tag/v0.3.61",
				"https://github.com/tzinfo/tzinfo/releases/tag/v1.2.10",
				"https://github.com/tzinfo/tzinfo/commit/ca29f349856d62cb2b2edb3257d9ddd2f97b3c27",
			},
		},
	}

	vulns, err := getVulnsForPurl("pkg:gem/tzinfo@1.2.5", newClient(&models.Credentials{}), orgID)

	assert.NoError(t, err)
	assert.Equal(t, expected, vulns)
}

func TestGetVulnsForPurlTimeout(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~\/issues\?version=`, httpmock.NewStringResponder(503, "Gateway Timeout"))

	vulns, err := getVulnsForPurl("pkg:gem/tzinfo@1.2.5", newClient(&models.Credentials{}), orgID)

	assert.Error(t, err)
	assert.Equal(t, "failed request while retrieving vulnerabilities (purl: pkg:gem/tzinfo@1.2.5, status: 503)", err.Error())
	assert.Nil(t, vulns)
}

func TestGetVulnsForPurlInvalidResponse(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", `=~\/issues\?version=`, httpmock.NewStringResponder(200, "BOOM"))

	vulns, err := getVulnsForPurl("pkg:gem/tzinfo@1.2.5", newClient(&models.Credentials{}), orgID)

	assert.Error(t, err)
	assert.Equal(t, "could not parse response (purl: pkg:gem/tzinfo@1.2.5): invalid character 'B' looking for beginning of value", err.Error())
	assert.Nil(t, vulns)
}

func TestGetVulnsForPurlInvalidPurl(t *testing.T) {
	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	vulns, err := getVulnsForPurl("foobar", newClient(&models.Credentials{}), orgID)

	assert.Error(t, err)
	assert.Equal(t, "invalid purl: scheme is missing", err.Error())
	assert.Nil(t, vulns)
}

func TestSnykIssueToBomberVuln(t *testing.T) {
	issue, err := snykIssueMock()
	assert.NoError(t, err)
	vuln := snykIssueToBomberVuln(issue)
	expected := models.Vulnerability{
		ID:          "SNYK-RUBY-TZINFO-2958048",
		Title:       "Directory Traversal",
		Description: "",
		Severity:    "HIGH",
		Cwe:         "CWE-22",
		CvssScore:   7.5,
		CvssVector:  "CVSS:3.1/AV:N/AC:H/PR:N/UI:R/S:U/C:H/I:H/A:H",
		Reference:   "https://security.snyk.io/vuln/SNYK-RUBY-TZINFO-2958048",
		ExternalReferences: []interface{}{
			"https://github.com/tzinfo/tzinfo/releases/tag/v0.3.61",
			"https://github.com/tzinfo/tzinfo/releases/tag/v1.2.10",
			"https://github.com/tzinfo/tzinfo/commit/ca29f349856d62cb2b2edb3257d9ddd2f97b3c27",
		},
	}

	assert.Equal(t, expected, vuln)
}

func TestSnykIssueToBomberVulnModerate(t *testing.T) {
	issue, err := snykIssueMock()
	assert.NoError(t, err)
	issue.Attributes.EffectiveSeverityLevel = "medium"

	vuln := snykIssueToBomberVuln(issue)

	assert.Equal(t, "MODERATE", vuln.Severity)
}

func TestSnykIssueToBomberVulnMissingCwe(t *testing.T) {
	issue, err := snykIssueMock()
	assert.NoError(t, err)
	issue.Attributes.Problems = []Problem{}

	vuln := snykIssueToBomberVuln(issue)

	assert.Equal(t, "", vuln.Cwe)
}

func TestSnykIssueToBomberVulnSnykSeverity(t *testing.T) {
	tc := []struct {
		Title             string
		Severities        []Severity
		ExpectedCvssScore float64
	}{
		{
			"prefer Snyk score",
			[]Severity{
				{Source: "SUSE", Score: 7},
				{Source: "Snyk", Score: 8},
				{Source: "NVD", Score: 9},
			},
			float64(8),
		},
		{
			"prefer NVD score",
			[]Severity{
				{Source: "SUSE", Score: 7},
				{Source: "NVD", Score: 9},
			},
			float64(9),
		},
		{
			"fallback on other",
			[]Severity{
				{Source: "SUSE", Score: 7},
			},
			float64(7),
		},
		{
			"empty severities", // edge case, should not happen
			[]Severity{},
			float64(0),
		},
	}
	issue, err := snykIssueMock()
	assert.NoError(t, err)

	for _, tt := range tc {
		t.Run(tt.Title, func(t *testing.T) {
			issue.Attributes.Severities = tt.Severities
			vuln := snykIssueToBomberVuln(issue)
			assert.Equal(t, tt.ExpectedCvssScore, vuln.CvssScore)
		})
	}
}

func TestSnykIssueToBomberVulnOtherSeverity(t *testing.T) {
	issue, err := snykIssueMock()
	assert.NoError(t, err)
	issue.Attributes.Severities = []Severity{
		{Source: "SUSE", Score: 7},
	}

	vuln := snykIssueToBomberVuln(issue)

	assert.Equal(t, float64(7), vuln.CvssScore)
}

func TestValidatePurl(t *testing.T) {
	t.Run("should raise error for invalid purl", func(t *testing.T) {
		err := validatePurl("foobar")

		assert.Equal(t, "invalid purl: scheme is missing", err.Error())
	})

	t.Run("should not raise error for valid purl", func(t *testing.T) {
		err := validatePurl("pkg:gem/tzinfo@1.2.5")

		assert.NoError(t, err)
	})
}

func snykIssueMock() (issue SnykIssueResource, err error) {
	var doc SnykIssuesDocument
	if err := json.Unmarshal(issuesResponse, &doc); err != nil {
		return issue, err
	}
	return doc.Data[0], nil
}
