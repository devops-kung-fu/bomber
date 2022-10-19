package snyk

import (
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/remeh/sizedwaitgroup"

	"github.com/devops-kung-fu/bomber/models"
)

const (
	SNYK_URL         = "https://api.snyk.io/rest"
	SNYK_API_VERSION = "?version=2022-09-15~experimental"
	CONCURRENCY      = 10
)

type Provider struct{}

// Info provides basic information about the Snyk Provider
func (Provider) Info() string {
	return "Snyk (https://security.snyk.io)"
}

// Scan scans a list of Purls for vulnerabilities against Snyk.
func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	if err = validateCredentials(credentials); err != nil {
		return packages, fmt.Errorf("Could not validate credentials: %w", err)
	}

	wg := sizedwaitgroup.New(CONCURRENCY)
	client := newClient(credentials)
	orgID, err := getOrgID(client)
	if err != nil {
		return packages, fmt.Errorf("Could not infer user’s Snyk organization: %w", err)
	}

	for _, pp := range purls {
		wg.Add()

		go func(purl string) {
			defer wg.Done()

			vulns, err := getVulnsForPurl(purl, client, orgID)
			if err != nil {
				log.Printf("Could not get vulnerabilities for package (%s): %s\n", purl, err.Error())
			}

			if len(vulns) == 0 {
				return
			}

			packages = append(packages, models.Package{
				Purl:            purl,
				Vulnerabilities: vulns,
			})
		}(pp)
	}

	wg.Wait()
	return
}

func validateCredentials(credentials *models.Credentials) error {
	if credentials == nil {
		return errors.New("credentials cannot be nil")
	}

	if credentials.Token == "" {
		credentials.Token = os.Getenv("SNYK_TOKEN")
	}

	if credentials.Token == "" {
		credentials.Token = os.Getenv("BOMBER_PROVIDER_TOKEN")
	}

	if credentials.Token == "" {
		return errors.New("bomber requires a token to use the Snyk provider")
	}

	return nil
}
