package filters

import (
	"github.com/devops-kung-fu/bomber/models"
)

func Ignore(vulnerabilities []models.Vulnerability, cves []string) (filtered []models.Vulnerability, err error) {
	for i, v := range vulnerabilities {
		for _, cve := range cves {
			if v.ID == cve {
				break
			} else {
				filtered = append(filtered, vulnerabilities[i])
			}
		}
	}
	return
}
