package osv

import (
	"encoding/json"
	"fmt"
	"log"
	"strings"

	"github.com/kirinlabs/HttpRequest"
	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

const OSV_URL = "https://api.osv.dev/v1/query"

// Provider represents the OSSIndex provider
type Provider struct{}

// Query is used for the request sent to the OSV
type Query struct {
	Version string `json:"version"`
	Package Pkg    `json:"package"`
}

// Pkg contains a name of the package that OSV process
type Pkg struct {
	Name string `json:"name"`
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
	Name      string `json:"name"`
	Ecosystem string `json:"ecosystem"`
	Purl      string `json:"purl"`
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

// Info provides basic information about the OSVProvider
func (Provider) Info() string {
	return "OSV Vulnerability Database (https://osv.dev)"
}

// Scan scans a list of Purls for vulnerabilities against OSV.dev. Note that credentials are not needed for OSV, so can be nil.
func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	for _, pp := range purls {
		purl, e := packageurl.FromString(pp)
		if e != nil {
			err = e
			return
		}
		p := Pkg{
			Name: purl.Name,
		}
		q := Query{
			Package: p,
			Version: purl.Version,
		}
		req := HttpRequest.NewRequest()
		log.Println(q)
		resp, _ := req.JSON().Post(OSV_URL, q)
		defer func() {
			_ = resp.Close()
		}()

		log.Printf("OSV Response Status: %v", resp.StatusCode())

		body, _ := resp.Body()
		if resp.StatusCode() == 200 {
			log.Println("Body:", string(body))
			var response Response
			err = json.Unmarshal(body, &response)
			if err != nil {
				return
			}
			if len(response.Vulns) > 0 {
				pkg := models.Package{
					Purl: pp,
				}
				for _, v := range response.Vulns {
					vuln := models.Vulnerability{
						ID:          strings.Join(v.Aliases, ","),
						Title:       v.Summary,
						Description: v.Details,
						Cwe:         strings.Join(v.DatabaseSpecific.CweIDS, ","),
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
	return
}
