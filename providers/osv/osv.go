// Package osv contains functionality to retrieve vulnerability information from OSV.dev
package osv

import (
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	osvscanner "github.com/google/osv-scanner/pkg/osv"

	m "github.com/devops-kung-fu/bomber/models"
)

const osvURL = "https://api.osv.dev/v1/query"

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
		"almalinux",
		"alpine",
		"android",
		"bitnami",
		"cargo",
		"curl",
		"debian",
		"git",
		"github-actions",
		"go",
		"haskell",
		"hex",
		"linux",
		"maven",
		"npm",
		"nuget",
		"oss-fuzz",
		"packagist",
		"pub",
		"pypi",
		"python",
		"cran",
		"rocky",
		"rubygems",
		"swift",
		"ubuntu",
	}
}

// Info provides basic information about the OSVProvider
func (Provider) Info() string {
	return "OSV Vulnerability Database (https://osv.dev)"
}

// Scan scans a lisst of Purls for vulnerabilities against OSV.dev. Note that credentials are not needed for OSV, so can be nil.
func (Provider) Scan(purls []string, credentials *m.Credentials) ([]m.Package, error) {
	var query osvscanner.BatchedQuery
	for _, purl := range purls {
		purlQuery := osvscanner.MakePURLRequest(purl)
		query.Queries = append(query.Queries, purlQuery)
	}
	httpClient := client.GetClient()
	resp, err := osvscanner.MakeRequestWithClient(query, httpClient)
	if err != nil {
		return nil, fmt.Errorf("osv.dev batched request failed: %w", err)
	}

	hydrated, err := osvscanner.HydrateWithClient(resp, httpClient)

	if err != nil {
		return nil, fmt.Errorf("osv.dev hydration request failed: %w", err)
	}

	packages := []m.Package{}
	for i, r := range hydrated.Results {
		if len(r.Vulns) > 0 {
			pkg := m.Package{
				Purl:            query.Queries[i].Package.PURL,
				Vulnerabilities: []m.Vulnerability{},
			}
			for _, vuln := range r.Vulns {
				severity, ok := vuln.DatabaseSpecific["severity"].(string)
				if !ok {
					severity = "UNSPECIFIED"
				}
				vulnerability := m.Vulnerability{
					ID: func() string {
						for _, alias := range vuln.Aliases {
							if strings.HasPrefix(strings.ToLower(alias), "cve") {
								return alias
							}
						}
						if vuln.ID == "" {
							return "NOT PROVIDED"
						}
						return vuln.ID
					}(),
					Title:       vuln.Summary,
					Description: vuln.Details,
					Severity:    severity,
					Cve: func() string {
						if len(vuln.Aliases) > 0 {
							return strings.Join(vuln.Aliases, ",")
						}
						return "NOT PROVIDED"
					}(),
					CvssScore: func() float64 {
						s, ok := vuln.DatabaseSpecific["cvss_score"].(string)
						if ok {
							score, _ := strconv.ParseFloat(s, 64)
							return score
						}
						return 0.0
					}(),
				}
				if vulnerability.ID == "" && len(vuln.DatabaseSpecific["cwe_ids"].([]interface{})) > 0 {
					cweIDs := make([]string, len(vuln.DatabaseSpecific["cwe_ids"].([]interface{})))
					for i, cweID := range vuln.DatabaseSpecific["cwe_ids"].([]interface{}) {
						cweIDs[i] = cweID.(string)
					}
					vulnerability.ID = strings.Join(cweIDs, ",")
				}
				pkg.Vulnerabilities = append(pkg.Vulnerabilities, vulnerability)
			}
			packages = append(packages, pkg)
		}
	}

	return packages, nil
}
