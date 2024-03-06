// package openai enriches vulnerability information
package openai

import "github.com/devops-kung-fu/bomber/models"

// Provider represents the openai enricher
type Enricher struct{}

// Enrich adds additional information to vulnerabilities
func (Enricher) Enrich(vulnerabilities []models.Vulnerability, credentials *models.Credentials) ([]models.Vulnerability, error) {

	return nil, nil
}
