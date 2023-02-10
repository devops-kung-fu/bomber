// Package filters provides functionality to filter vulnerability output
package filters

import (
	"github.com/devops-kung-fu/bomber/models"
)

// Ignore goes through a list of vulnerabilities and ignores those that have a CVE listed in an ignore file
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
