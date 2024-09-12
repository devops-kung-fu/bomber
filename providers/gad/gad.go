// Package gad contains functionality to retrieve vulnerability information from the GitHub Advisory Database
package gad

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"

	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

//var client *resty.Client

func init() {
	//client = resty.New().
	//	SetTransport(&http.Transport{TLSHandshakeTimeout: 60 * time.Second})
}

// Provider represents the OSSIndex provider
type Provider struct{}

// Info provides basic information about the GAD Provider
func (Provider) Info() string {
	return "GitHub Advisory Database (https://github.com/advisories)"
}

func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	for _, purl := range purls {
		response, e := queryGitHubAdvisories(purl, *credentials)
		if e != nil {
			fmt.Printf("Error: %v\n", err)
			return
		}

		fmt.Printf("Vulnerabilities for %s:\n", purl)
		for _, edge := range response.Data.SecurityVulnerabilities.Edges {
			advisory := edge.Node.Advisory
			fmt.Printf("Summary: %s\n", advisory.Summary)
			fmt.Printf("Severity: %s\n", advisory.Severity)
			for _, identifier := range advisory.Identifiers {
				if identifier.Type == "CVE" {
					fmt.Printf("CVE: %s\n", identifier.Value)
				}
			}
			fmt.Println("---")
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
		"ecosystem": p.Type,
		"package":   p.Name,
	}

	requestBody, err := json.Marshal(GraphQLRequest{Query: query, Variables: variables})
	if err != nil {
		return nil, fmt.Errorf("error marshalling request: %v", err)
	}

	req, err := http.NewRequest("POST", githubGraphQLEndpoint, bytes.NewBuffer(requestBody))
	if err != nil {
		return nil, fmt.Errorf("error creating request: %v", err)
	}

	token := credentials.ProviderToken
	if token == "" {
		return nil, fmt.Errorf("The Github Advisory Database provider requires a token")
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error sending request: %v", err)
	}
	defer resp.Body.Close()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error reading response: %v", err)
	}

	var graphQLResponse GraphQLResponse
	err = json.Unmarshal(body, &graphQLResponse)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling response: %v", err)
	}

	return &graphQLResponse, nil
}
