// Package snyk contains functionality to retrieve vulnerability information from Snyk
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
	SnykURL        = "https://api.snyk.io/rest"
	SnykAPIVersion = "?version=2022-09-15~experimental"
	Concurrency    = 10
)

type Provider struct{}

// Info provides basic information about the Snyk Provider
func (Provider) Info() string {
	return "Snyk (https://security.snyk.io)"
}

func (Provider) SupportedEcosystems() []string {
	return []string{
		"npm",
		"maven",
		"cocoapods",
		"composer",
		"rubygems",
		"nuget",
		"pypi",
		"hex",
		"cargo",
		"swift",
		"conan",
		"apk",
		"deb",
		"docker",
		"rpm",
	}
}

// Scan scans a list of Purls for vulnerabilities against Snyk.
func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	if err = validateCredentials(credentials); err != nil {
		return packages, fmt.Errorf("could not validate credentials: %w", err)
	}
	wg := sizedwaitgroup.New(Concurrency)

	orgID, err := getOrgID(credentials.ProviderToken)
	if err != nil {
		return packages, fmt.Errorf("could not infer user’s Snyk organization: %w", err)
	}

	for _, pp := range purls {
		wg.Add()

		go func(purl string) {
			defer wg.Done()

			vulns, err := getVulnsForPurl(purl, orgID, credentials.ProviderToken)
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

	if credentials.ProviderToken == "" {
		credentials.ProviderToken = os.Getenv("SNYK_TOKEN")
	}

	if credentials.ProviderToken == "" {
		credentials.ProviderToken = os.Getenv("BOMBER_PROVIDER_TOKEN")
	}

	if credentials.ProviderToken == "" {
		return errors.New("bomber requires a token to use the Snyk provider")
	}

	return nil
}
