package snyk

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/go-resty/resty/v2"
	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

type SnykIssueResource struct {
	Attributes struct {
		Coordinates []Coordinate `json:"coordinates,omitempty"`
		CreatedAt   time.Time    `json:"created_at,omitempty"`

		// A description of the issue in Markdown format
		Description string `json:"description,omitempty"`

		// The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
		EffectiveSeverityLevel EffectiveSeverityLevel `json:"effective_severity_level,omitempty"`

		// The Snyk vulnerability ID.
		Key      string    `json:"key,omitempty"`
		Problems []Problem `json:"problems,omitempty"`

		// The severity level of the vulnerability: ‘low’, ‘medium’, ‘high’ or ‘critical’.
		Severities []Severity `json:"severities,omitempty"`
		Slots      Slots      `json:"slots,omitempty"`

		// A human-readable title for this issue.
		Title string `json:"title,omitempty"`

		// The issue type
		Type string `json:"type,omitempty"`

		// When the vulnerability information was last modified.
		UpdatedAt *string `json:"updated_at,omitempty"`
	} `json:"attributes,omitempty"`

	// The Snyk ID of the vulnerability.
	ID string `json:"id,omitempty"`

	// The type of the REST resource. Always ‘issue’.
	Type string `json:"type,omitempty"`
}

type Coordinate struct {
	Remedies []Remedy `json:"remedies,omitempty"`

	// The affected versions of this vulnerability.
	Representation []string `json:"representation,omitempty"`
}

type IssuesMeta struct {
	Package PackageMeta `json:"package,omitempty"`
}

type Problem struct {
	// When this problem was disclosed to the public.
	DisclosedAt time.Time `json:"disclosed_at,omitempty"`

	// When this problem was first discovered.
	DiscoveredAt time.Time `json:"discovered_at,omitempty"`
	ID           string    `json:"id"`
	Source       string    `json:"source"`

	// When this problem was last updated.
	UpdatedAt time.Time `json:"updated_at,omitempty"`

	// An optional URL for this problem.
	URL *string `json:"url,omitempty"`
}

type Remedy struct {
	// A markdown-formatted optional description of this remedy.
	Description string `json:"description,omitempty"`
	Details     struct {
		// A minimum version to upgrade to in order to remedy the issue.
		UpgradePackage string `json:"upgrade_package,omitempty"`
	} `json:"details,omitempty"`

	// The type of the remedy. Always ‘indeterminate’.
	Type string `json:"type,omitempty"`
}

type Severity struct {
	Level string `json:"level,omitempty"`

	// The CVSSv3 value of the vulnerability.
	Score float64 `json:"score,omitempty"`

	// The source of this severity. The value must be the id of a referenced problem or class, in which case that problem or class is the source of this issue. If source is omitted, this severity is sourced internally in the Snyk application.
	Source string `json:"source,omitempty"`

	// The CVSSv3 value of the vulnerability.
	Vector string `json:"vector,omitempty"`
}

type Slots struct {
	// The time at which this vulnerability was disclosed.
	DisclosureTime time.Time `json:"disclosure_time,omitempty"`

	// The exploit maturity. Value of ‘No Data’, ‘Not Defined’, ‘Unproven’, ‘Proof of Concept’, ‘Functional’ or ‘High’.
	Exploit string `json:"exploit,omitempty"`

	// The time at which this vulnerability was published.
	PublicationTime string `json:"publication_time,omitempty"`
	References      []struct {
		// Descriptor for an external reference to the issue
		Title string `json:"title,omitempty"`

		// URL for an external reference to the issue
		URL string `json:"url,omitempty"`
	} `json:"references,omitempty"`
}

const (
	Critical EffectiveSeverityLevel = "critical"
	High     EffectiveSeverityLevel = "high"
	Info     EffectiveSeverityLevel = "info"
	Low      EffectiveSeverityLevel = "low"
	Medium   EffectiveSeverityLevel = "medium"
)

// EffectiveSeverityLevel The type from enumeration of the issue’s severity level. This is usually set from the issue’s producer, but can be overridden by policies.
type EffectiveSeverityLevel string

type SnykIssuesDocument struct {
	Data    []SnykIssueResource `json:"data,omitempty"`
	Jsonapi JSONAPI             `json:"jsonapi,omitempty"`
	Links   *PaginatedLinks     `json:"links,omitempty"`
	Meta    *IssuesMeta         `json:"meta,omitempty"`
}

func getVulnsForPurl(
	purl string,
	orgID string,
	token string,
) (vulns []models.Vulnerability, err error) {
	if err := validatePurl(purl); err != nil {
		return nil, err
	}

	issuesURL := fmt.Sprintf(
		"%s/rest/orgs/%s/packages/%s/issues%s",
		getSnykAPIURL(), orgID, url.QueryEscape(purl), SnykAPIVersion,
	)

	client := resty.New()
	client.Debug = true

	resp, err := client.R().
		SetHeader("User-Agent", "bomber").
		SetAuthScheme("token").
		SetAuthToken(token).
		Get(issuesURL)

	if err != nil {
		log.Print(err)
		return nil, err
	}

	if resp.StatusCode() == http.StatusOK {
		var response SnykIssuesDocument
		if err = json.Unmarshal(resp.Body(), &response); err != nil {
			log.Println("Error:", err)
			return nil, err
		}

		for _, v := range response.Data {
			vuln := snykIssueToBomberVuln(v)
			vulns = append(vulns, vuln)
		}

		return vulns, nil
	} else {
		log.Println("Error: unexpected status code", resp.StatusCode())
		return nil, errors.New("unexpected status code")
	}
}

func validatePurl(purl string) error {
	if _, err := packageurl.FromString(purl); err != nil {
		return fmt.Errorf("invalid purl: %w", err)
	}
	return nil
}

func snykIssueToBomberVuln(v SnykIssueResource) models.Vulnerability {
	cvss := getCvss(v)
	severity := strings.ToUpper(string(v.Attributes.EffectiveSeverityLevel))

	if severity == "MEDIUM" {
		severity = "MODERATE"
	}

	return models.Vulnerability{
		ID:                 v.ID,
		Title:              v.Attributes.Title,
		Description:        v.Attributes.Description,
		Severity:           severity,
		Cwe:                getCwe(v),
		Cve:                getCve(v),
		CvssScore:          float64(cvss.Score),
		CvssVector:         cvss.Vector,
		Reference:          fmt.Sprintf("https://security.snyk.io/vuln/%s", v.ID),
		ExternalReferences: getExternalReferences(v),
	}
}

func getCwe(i SnykIssueResource) string {
	for _, p := range i.Attributes.Problems {
		if p.Source == "CWE" {
			return p.ID
		}
	}
	return ""
}

func getCve(i SnykIssueResource) string {
	for _, p := range i.Attributes.Problems {
		if p.Source == "CVE" {
			return p.ID
		}
	}
	return ""
}

func getCvss(i SnykIssueResource) *Severity {
	var nvdSeverity *Severity
	for _, ss := range i.Attributes.Severities {
		switch ss.Source {
		case "Snyk":
			return &ss
		case "NVD":
			nvdSeverity = &ss
		}
	}
	if nvdSeverity != nil {
		return nvdSeverity
	}
	if len(i.Attributes.Severities) > 0 {
		return &i.Attributes.Severities[0]
	}
	return &Severity{}
}

func getExternalReferences(i SnykIssueResource) (refs []interface{}) {
	for _, r := range i.Attributes.Slots.References {
		refs = append(refs, r.URL)
	}
	return refs
}
