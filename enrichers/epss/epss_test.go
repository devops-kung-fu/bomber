package epss

import (
	"testing"

	"github.com/jarcoal/httpmock"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestEnrich(t *testing.T) {
	enricher := Enricher{}
	vulnerabilities := []models.Vulnerability{
		{
			Cve: "CVE-2021-43138",
		},
		{
			Cve: "CVE-2020-15084",
		},
		{
			Cve: "CVE-2020-28282",
		},
		{
			Cve: "sonatype-2020-1214",
		},
	}

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://api.first.org/data/v1/epss",
		httpmock.NewBytesResponder(200, epssTestResponse()))

	enriched, err := enricher.Enrich(vulnerabilities, nil)

	assert.NoError(t, err)
	assert.Len(t, enriched, 4)

	assert.Empty(t, enriched[3].Epss.Cve)
	assert.Equal(t, enriched[0].Epss.Cve, "CVE-2021-43138")

}

func TestEnrich_Error(t *testing.T) {

	httpmock.Activate()
	defer httpmock.DeactivateAndReset()

	httpmock.RegisterResponder("GET", "https://api.first.org/data/v1/epss",
		httpmock.NewBytesResponder(404, []byte{}))

	cves := []string{"CVE-2021-43138", "CVE-2020-15084", "CVE-2020-28282", "sonatype-2020-1214"}
	_, err := fetchEpssData(cves)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "EPSS API request failed with status code")
}

func epssTestResponse() []byte {
	response := `
	[
		// {
		// 	"coordinates": "pkg:gem/tzinfo@1.2.5",
		// 	"description": "TZInfo provides daylight savings aware transformations between times in different time zones.",
		// 	"reference": "https://ossindex.sonatype.org/component/pkg:gem/tzinfo@1.2.5?utm_source=mozilla&utm_medium=integration&utm_content=5.0",
		// 	"vulnerabilities": [
		// 	{
		// 		"id": "CVE-2022-31163",
		// 		"displayName": "CVE-2022-31163",
		// 		"title": "[CVE-2022-31163] CWE-22: Improper Limitation of a Pathname to a Restricted Directory ('Path Traversal')",
		// 		"description": "TZInfo... ",
		// 		"cvssScore": 8.1,
		// 		"cvssVector": "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H",
		// 		"cwe": "CWE-22",
		// 		"cve": "CVE-2022-31163",
		// 		"reference": "https://ossindex.sonatype.org/vulnerability/CVE-2022-31163?component-type=gem&component-name=tzinfo&utm_source=mozilla&utm_medium=integration&utm_content=5.0",
		// 		"externalReferences": [
		// 			"http://web.nvd.nist.gov/view/vuln/detail?vulnId=CVE-2022-31163",
		// 			"https://github.com/tzinfo/tzinfo/releases/tag/v0.3.61",
		// 			"https://github.com/tzinfo/tzinfo/releases/tag/v1.2.10",
		// 			"https://github.com/tzinfo/tzinfo/security/advisories/GHSA-5cm2-9h8c-rvfx"
		// 		]
		// 	}
		// 	]
		// }
	]`
	return []byte(response)
}
