// Package osv contains functionality to retrieve vulnerability information from OSV.dev
package osv

import (
	"encoding/json"
	"fmt"
	"log"
	"strconv"
	"strings"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const osvURL = "https://api.osv.dev/v1/query"

// Provider represents the OSSIndex provider
type Provider struct{}

// Query is used for the request sent to the OSV
type Query struct {
	Version string       `json:"version"`
	Package PackageClass `json:"package"`
}

// Response encapsulates the vulnerabilities returned by OSV
type Response struct {
	Vulns []Vuln `json:"vulns"`
}

// Vuln represents a vulnerability
type Vuln struct {
	ID               string               `json:"id"`
	Summary          string               `json:"summary"`
	Details          string               `json:"details"`
	Modified         string               `json:"modified"`
	Published        string               `json:"published"`
	DatabaseSpecific VulnDatabaseSpecific `json:"database_specific"`
	References       []Reference          `json:"references"`
	Affected         []Affected           `json:"affected"`
	SchemaVersion    string               `json:"schema_version"`
	Aliases          []string             `json:"aliases"`
	Severity         []Severity           `json:"severity"`
}

type Affected struct {
	Package          PackageClass             `json:"package"`
	Ranges           []Range                  `json:"ranges"`
	DatabaseSpecific AffectedDatabaseSpecific `json:"database_specific"`
	Versions         []string                 `json:"versions"`
}

type AffectedDatabaseSpecific struct {
	LastKnownAffectedVersionRange *string `json:"last_known_affected_version_range,omitempty"`
	Source                        string  `json:"source"`
}

type PackageClass struct {
	Name      string `json:"name,omitempty"`
	Ecosystem string `json:"ecosystem,omitempty"`
	Purl      string `json:"purl,omitempty"`
}

type Range struct {
	Type   string  `json:"type"`
	Events []Event `json:"events"`
}

type Event struct {
	Introduced string `json:"introduced"`
}

type VulnDatabaseSpecific struct {
	Severity       string   `json:"severity"`
	CweIDS         []string `json:"cwe_ids"`
	GithubReviewed bool     `json:"github_reviewed"`
}

type Reference struct {
	Type Type   `json:"type"`
	URL  string `json:"url"`
}

// Severity provides the severity score of the vulnerability
type Severity struct {
	Type  string `json:"type"`
	Score string `json:"score"`
}

type Type string

const (
	Advisory Type = "ADVISORY"
	Package  Type = "PACKAGE"
	Web      Type = "WEB"
)

func ToVDR(vulns []Vuln) (vdr *cyclone.BOM) {
	vdr = cyclone.NewBOM()
	vulnerabilities := make([]cyclone.Vulnerability, 0)
	vdr.Vulnerabilities = &vulnerabilities
	for _, v := range vulns {
		vuln := &cyclone.Vulnerability{
			BOMRef:         "",
			ID:             v.Aliases[0],
			Source:         &cyclone.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + v.Aliases[0]},
			References:     &[]cyclone.VulnerabilityReference{},
			Ratings:        &[]cyclone.VulnerabilityRating{},
			CWEs:           CWEStringToInt(v.DatabaseSpecific.CweIDS),
			Description:    v.Summary,
			Detail:         v.Details,
			Recommendation: "",
			Advisories:     &[]cyclone.Advisory{},
			Created:        "",
			Published:      v.Published,
			Updated:        v.Modified,
			Credits:        &cyclone.Credits{},
			Tools: &[]cyclone.Tool{
				{
					Vendor:  "DKFM",
					Name:    "bomber",
					Version: "1.0.0", //TODO: Fill this in during render
					Hashes:  &[]cyclone.Hash{},
					ExternalReferences: &[]cyclone.ExternalReference{
						{
							URL:     "https://github.com/devops-kung-fu/bomber",
							Comment: "bomber GitHub repository",
							Hashes:  &[]cyclone.Hash{},
							Type:    "support",
						},
					},
				},
			},
			//TODO: Put this in the command as a flag --analysis
			// Analysis: &cyclone.VulnerabilityAnalysis{ //If someone fills this out, it's a VEX
			// 	State:         "-",
			// 	Justification: "-",
			// 	Response: &[]cyclone.ImpactAnalysisResponse{
			// 		"-",
			// 	},
			// 	Detail: "-",
			// },
			Affects:    &[]cyclone.Affects{},
			Properties: &[]cyclone.Property{},
		}
		*vdr.Vulnerabilities = append(*vdr.Vulnerabilities, *vuln)
	}
	return
}

func CWEStringToInt(cweStrings []string) *[]int {
	cwes := make([]int, 0, len(cweStrings))
	for _, cweString := range cweStrings {
		cweInt, err := strconv.Atoi(strings.TrimPrefix(cweString, "CWE-"))
		if err != nil {
			log.Printf("Error converting %s to int: %v\n", cweString, err)
			continue
		}
		cwes = append(cwes, cweInt)
	}
	return &cwes
}

// Info provides basic information about the OSVProvider
func (Provider) Info() string {
	return "OSV Vulnerability Database (https://osv.dev)"
}

// Scan scans a list of Purls for vulnerabilities against OSV.dev. Note that credentials are not needed for OSV, so can be nil.
func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	vulns := []Vuln{}
	for _, pp := range purls {
		log.Println("Purl:", pp)
		q := Query{
			Package: PackageClass{
				Purl: pp,
			},
		}
		req := HttpRequest.NewRequest()
		log.Printf("OSV Query: %v", q)
		resp, _ := req.JSON().Post(osvURL, q)
		defer func() {
			_ = resp.Close()
		}()

		log.Printf("OSV Response Status: %v", resp.StatusCode())

		body, _ := resp.Body()
		if resp.StatusCode() == 200 {
			var response Response
			err = json.Unmarshal(body, &response)

			if err != nil {
				return
			}
			if len(response.Vulns) > 0 {
				vulns = append(vulns, response.Vulns...)
				pkg := models.Package{
					Purl: pp,
				}
				for _, v := range response.Vulns {
					vuln := models.Vulnerability{
						ID:          strings.Join(v.Aliases, ","),
						Title:       v.Summary,
						Description: v.Details,
						Cwe:         strings.Join(v.DatabaseSpecific.CweIDS, ","),
						Cve:         strings.Join(v.Aliases, ","),
						Severity:    v.DatabaseSpecific.Severity,
					}
					if vuln.Severity == "" {
						vuln.Severity = "UNSPECIFIED"
					}
					if vuln.ID == "" {
						vuln.ID = strings.Join(v.DatabaseSpecific.CweIDS, ",")
					}
					if vuln.ID == "" {
						vuln.ID = "NOT PROVIDED"
					}
					pkg.Vulnerabilities = append(pkg.Vulnerabilities, vuln)
				}
				packages = append(packages, pkg)
			}
		} else {
			err = fmt.Errorf("error retrieving vulnerability data (%v)", resp.Response().Status)
			break
		}
	}
	log.Println(ToVDR(vulns))
	return
}
