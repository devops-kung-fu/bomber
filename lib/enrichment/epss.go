// Package enrichment contains functionality to enrich vulnerability data from other sources
package enrichment

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const epssBaseURL = "https://api.first.org/data/v1/epss?cve="

// Enrich adds epss score data to vulnerabilities
func Enrich(vulnerabilities []models.Vulnerability) ([]models.Vulnerability, error) {
	identifiers := make([]string, len(vulnerabilities))
	for i, v := range vulnerabilities {
		identifiers[i] = v.Cve
	}

	req := HttpRequest.NewRequest()
	resp, _ := req.JSON().Get(fmt.Sprintf("%s%s", epssBaseURL, strings.Join(identifiers, ",")))
	defer func() {
		_ = resp.Close()
	}()

	log.Println("EPSS Response Status:", resp.StatusCode())

	body, _ := resp.Body()
	if resp.StatusCode() == 200 {
		var epss models.Epss
		if err := json.Unmarshal(body, &epss); err != nil {
			return nil, err
		}
		log.Println("EPSS response total:", epss.Total)

		for i, v := range vulnerabilities {
			for _, sv := range epss.Scores {
				if sv.Cve == v.Cve {
					vulnerabilities[i].Epss = sv
				}
			}
		}
		return vulnerabilities, nil
	}
	return nil, nil
}
