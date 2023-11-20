// Package enrichment provides functionality to enrich vulnerabilities with epss data.
package enrichment

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const (
	epssBaseURL = "https://api.first.org/data/v1/epss?cve="
	pageSize    = 150
)

// TODO: this needs to be refactored so we can batch the scanning and de-duplicate. Each component has it's own list of []models.Vulnerability and this function is called multiple times. At least the implementation here reduces the calls by batching per component.

// Enrich adds epss score data to vulnerabilities.
func Enrich(vulnerabilities []models.Vulnerability) ([]models.Vulnerability, error) {
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

func getCveBatch(vulnerabilities []models.Vulnerability) []string {
	identifiers := make([]string, len(vulnerabilities))
	for i, v := range vulnerabilities {
		identifiers[i] = v.Cve

	}
	return identifiers
}

func fetchEpssData(cves []string) (models.Epss, error) {
	req := HttpRequest.NewRequest()
	resp, err := req.JSON().Get(fmt.Sprintf("%s%s", epssBaseURL, strings.Join(cves, ",")))
	if err != nil {
		return models.Epss{}, err
	}
	defer func() {
		_ = resp.Close()
	}()

	log.Println("EPSS Response Status:", resp.StatusCode())

	body, _ := resp.Body()
	if resp.StatusCode() == 200 {
		var epss models.Epss
		if err := json.Unmarshal(body, &epss); err != nil {
			return models.Epss{}, err
		}
		return epss, nil
	}
	return models.Epss{}, fmt.Errorf("EPSS API request failed with status code: %d", resp.StatusCode())
}
