// Package gad contains functionality to retrieve vulnerability information from the GitHub Advisory Database
package gad

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

var client *resty.Client

func init() {
	// Cloning the transport ensures a proper working http client that respects the proxy settings
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 60 * time.Second
	client = resty.New().SetTransport(transport)
}

// Provider represents the OSSIndex provider
type Provider struct{}

func (Provider) SupportedEcosystems() []string {
	return []string{
		"github-actions",
		"composer",
		"erlang",
		"golang",
		"maven",
		"npm",
		"nuget",
		"pypi",
		"pypi",
		"rubygems",
		"cargo",
	}
}

// Info provides basic information about the GAD Provider
func (Provider) Info() string {
	return "GitHub Advisory Database (https://github.com/advisories)"
}

func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	if err = validateCredentials(credentials); err != nil {
		return
	}

	for _, purl := range purls {
		response, e := queryGitHubAdvisories(purl, *credentials)
		if e != nil {
			return nil, e
		}
		pkg := models.Package{
			Purl: purl,
		}
		for _, edge := range response.Data.SecurityVulnerabilities.Edges {
			log.Printf("Vulnerabilities for %s:\n", purl)
			//TODO: Add more information to the vulnerability struct and deduplicate
			vulnerability := models.Vulnerability{}

			advisory := edge.Node.Advisory
			vulnerability.DisplayName = advisory.Summary
			vulnerability.Description = advisory.Description
			vulnerability.Severity = advisory.Severity
			for _, identifier := range advisory.Identifiers {
				if identifier.Type == "CVE" {
					vulnerability.ID = identifier.Value
					vulnerability.Cve = identifier.Value
					vulnerability.Title = identifier.Value
				}
			}

			for _, identifier := range advisory.Identifiers {
				if identifier.Type == "CVE" {
					fmt.Printf("CVE: %s\n", identifier.Value)
				}
			}
			pkg.Vulnerabilities = append(pkg.Vulnerabilities, vulnerability)
		}
		if len(pkg.Vulnerabilities) > 0 {
			packages = append(packages, pkg)
		}
	}
	return
}

const githubGraphQLEndpoint = "https://api.github.com/graphql"

type GraphQLRequest struct {
	Query     string                 `json:"query"`
	Variables map[string]interface{} `json:"variables"`
}

type GraphQLResponse struct {
	Data struct {
		SecurityVulnerabilities struct {
			Edges []struct {
				Node struct {
					Advisory struct {
						Identifiers []struct {
							Type  string `json:"type"`
							Value string `json:"value"`
						} `json:"identifiers"`
						Summary     string `json:"summary"`
						Description string `json:"description"`
						Severity    string `json:"severity"`
					} `json:"advisory"`
				} `json:"node"`
			} `json:"edges"`
		} `json:"securityVulnerabilities"`
	} `json:"data"`
}

func queryGitHubAdvisories(purl string, credentials models.Credentials) (*GraphQLResponse, error) {
	p, err := packageurl.FromString(purl)
	if err != nil {
		return nil, fmt.Errorf("invalid PURL: %v", err)
	}

	query := `
	query($ecosystem: SecurityAdvisoryEcosystem!, $package: String!) {
		securityVulnerabilities(ecosystem: $ecosystem, package: $package, first: 100) {
			edges {
				node {
					advisory {
						identifiers {
							type
							value
						}
						summary
						description
						severity
					}
				}
			}
		}
	}
	`

	variables := map[string]interface{}{
		"ecosystem": strings.ToUpper(p.Type),
		"package":   p.Name,
	}

	requestBody, err := json.Marshal(GraphQLRequest{Query: query, Variables: variables})
	if err != nil {
		return nil, fmt.Errorf("error marshalling request: %v", err)
	}
	resp, _ := client.R().
		SetBody(requestBody).
		SetAuthToken(credentials.ProviderToken).
		Post(githubGraphQLEndpoint)

	var graphQLResponse GraphQLResponse
	if resp.StatusCode() == http.StatusOK {
		err = json.Unmarshal(resp.Body(), &graphQLResponse)
		if err != nil {
			return nil, fmt.Errorf("error unmarshalling response: %v", err)
		}
	} else {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode())
	}

	return &graphQLResponse, nil
}

func validateCredentials(credentials *models.Credentials) (err error) {
	if credentials.ProviderToken == "" {
		credentials.ProviderToken = os.Getenv("GITHUB_TOKEN")
	}

	if credentials.ProviderToken == "" {
		err = errors.New("bomber requires an GitHub PAT to utilize the GitHub Advisory Database")
	}
	return
}
