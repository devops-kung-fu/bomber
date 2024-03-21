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
