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

	cves := []string{"CVE-2023-22795", "CVE-2023-22792", "CVE-2022-23633", "CVE-2022-22577"}
	_, err := fetchEpssData(cves)
	assert.NoError(t, err)
}

func epssTestResponse() []byte {
	response := `
	{
		"status": "OK",
		"status-code": 200,
		"version": "1.0",
		"access-control-allow-headers": "x-requested-with",
		"access": "public",
		"total": 13,
		"offset": 0,
		"limit": 100,
		"data": [
			{
				"cve": "CVE-2023-22795",
				"epss": "0.027190000",
				"percentile": "0.906830000",
				"date": "2024-08-15"
			},
			{
				"cve": "CVE-2023-22792",
				"epss": "0.001150000",
				"percentile": "0.458150000",
				"date": "2024-08-15"
			},
			{
				"cve": "CVE-2022-23633",
				"epss": "0.002130000",
				"percentile": "0.597890000",
				"date": "2024-08-15"
			},
			{
				"cve": "CVE-2022-22577",
				"epss": "0.005230000",
				"percentile": "0.772150000",
				"date": "2024-08-15"
			}
		]
	}`
	return []byte(response)
}
