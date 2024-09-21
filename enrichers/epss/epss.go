// Package epss provides functionality to enrich vulnerabilities with epss data.
package epss

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/devops-kung-fu/bomber/models"
)

const (
	epssBaseURL = "https://api.first.org/data/v1/epss?cve="
	pageSize    = 150
)

// Provider represents an EPSS enricher
type Enricher struct{}

var client *resty.Client

func init() {
	// Cloning the transport ensures a proper working http client that respects the proxy settings
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 60 * time.Second
	client = resty.New().SetTransport(transport)
}

// TODO: this needs to be refactored so we can batch the scanning and de-duplicate. Each component has it's own list of []models.Vulnerability and this function is called multiple times. At least the implementation here reduces the calls by batching per component.

// Enrich adds epss score data to vulnerabilities.
func (Enricher) Enrich(vulnerabilities []models.Vulnerability, credentials *models.Credentials) ([]models.Vulnerability, error) {
	var enrichedVulnerabilities []models.Vulnerability

	for i := 0; i < len(vulnerabilities); i += pageSize {
		endIndex := i + pageSize

		if endIndex > len(vulnerabilities) {
			endIndex = len(vulnerabilities)
		}

		cvesBatch := getCveBatch(vulnerabilities[i:endIndex])

		epss, err := fetchEpssData(cvesBatch)
		if err != nil {
			return nil, err
		}

		log.Printf("%v EPSS responses for %v vulnerabilities", epss.Total, len(vulnerabilities))

		for i, v := range vulnerabilities {
			for _, sv := range epss.Scores {
				if sv.Cve == v.Cve {
					vulnerabilities[i].Epss = sv
				}
			}
		}

		enrichedVulnerabilities = append(enrichedVulnerabilities, vulnerabilities...)
	}

	return enrichedVulnerabilities, nil
}

// getCveBatch extracts CVE identifiers from a slice of Vulnerability models
// and returns a new slice containing only the CVE identifiers.
func getCveBatch(vulnerabilities []models.Vulnerability) []string {
	identifiers := make([]string, len(vulnerabilities))
	for i, v := range vulnerabilities {
		identifiers[i] = v.Cve
	}
	return identifiers
}

// fetchEpssData retrieves EPSS (Exploit Prediction Scoring System) data for
// a batch of CVEs from the EPSS API. It sends a GET request to the API with
// the specified CVEs, parses the JSON response, and returns an Epss model
// containing the fetched data. If the request or parsing fails, an error is returned.
func fetchEpssData(cves []string) (models.Epss, error) {

	// Create the URL by joining the base URL and CVEs.
	url := fmt.Sprintf("%s%s", epssBaseURL, strings.Join(cves, ","))

	resp, _ := client.R().
		Get(url)

	log.Println("EPSS Response Status:", resp.StatusCode())

	if resp.StatusCode() == http.StatusOK {
		var epss models.Epss
		if err := json.Unmarshal(resp.Body(), &epss); err != nil {
			return models.Epss{}, err
		}
		return epss, nil
	}

	return models.Epss{}, fmt.Errorf("EPSS API request failed with status code: %d", resp.StatusCode())
}
