// Package models contains structs and interfaces used by bomber
package models

import (
	"time"
)

// Package encapsulates information about a package/component and it's vulnerabilities
type Package struct {
	Purl            string          `json:"coordinates"`
	Reference       string          `json:"reference,omitempty"`
	Description     string          `json:"description,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

// Vulnerability encapsulates the information describing a detected vulnerability
type Vulnerability struct {
	ID                 string        `json:"id,omitempty"`
	DisplayName        string        `json:"displayName,omitempty"`
	Title              string        `json:"title,omitempty"`
	Description        string        `json:"description,omitempty"`
	CvssScore          float64       `json:"cvssScore,omitempty"`
	CvssVector         string        `json:"cvssVector,omitempty"`
	Cwe                string        `json:"cwe,omitempty"`
	Cve                string        `json:"cve,omitempty"`
	Reference          string        `json:"reference,omitempty"`
	ExternalReferences []interface{} `json:"externalReferences,omitempty"`
	Severity           string        `json:"severity,omitempty"`
	Epss               EpssScore     `json:"epss,omitempty"`
}

// Summary is a struct used to keep track of severity counts
type Summary struct {
	Unspecified int
	Low         int
	Moderate    int
	High        int
	Critical    int
}

// Results is the high level JSON object used to define vulnerabilities processed by bomber.
type Results struct {
	Meta     Meta          `json:"meta,omitempty"`
	Files    []ScannedFile `json:"files,omitempty"`
	Licenses []string      `json:"licenses,omitempty"`
	Summary  Summary       `json:"summary,omitempty"`
	Packages []Package     `json:"packages,omitempty"`
}

// Meta contains system and execution information about the results from bomber
type Meta struct {
	Generator      string    `json:"generator"`
	URL            string    `json:"url"`
	Version        string    `json:"version"`
	Provider       string    `json:"provider"`
	SeverityFilter string    `json:"severityFilter"`
	Date           time.Time `json:"date"`
}

// ScannedFile contains the absolute name and sha256 of a processed file
type ScannedFile struct {
	Name   string `json:"name"`
	SHA256 string `json:"sha256"`
}

// Credentials the user credentials used by a provider to authenticate to an API
type Credentials struct {
	Username      string
	ProviderToken string
	OpenAIAPIKey  string
}

// NewResults defines the high level output of bomber
func NewResults(packages []Package, summary Summary, scanned []ScannedFile, licenses []string, version, providerName string, severityFilter string) Results {
	return Results{
		Meta: Meta{
			Generator:      "bomber",
			URL:            "https://github.com/devops-kung-fu/bomber",
			Version:        version,
			Provider:       providerName,
			Date:           time.Now(),
			SeverityFilter: severityFilter,
		},
		Files:    scanned,
		Summary:  summary,
		Packages: packages,
		Licenses: licenses,
	}
}

// Epss encapsulates the response of a query to the Epss scoring API
type Epss struct {
	Status     string      `json:"status,omitempty"`
	StatusCode int64       `json:"status-code,omitempty"`
	Version    string      `json:"version,omitempty"`
	Access     string      `json:"access,omitempty"`
	Total      int64       `json:"total,omitempty"`
	Offset     int64       `json:"offset,omitempty"`
	Limit      int64       `json:"limit,omitempty"`
	Scores     []EpssScore `json:"data,omitempty"`
}

// EpssScore contains epss score data for a specific CVE
type EpssScore struct {
	Cve        string `json:"cve,omitempty"`
	Epss       string `json:"epss,omitempty"`
	Percentile string `json:"percentile,omitempty"`
	Date       string `json:"date,omitempty"`
}

// Issue encapsulates an issue with the processing of an SBOM
type Issue struct {
	Err       error  `json:"error,omitempty"`
	IssueType string `json:"issueType,omitempty"`
	Purl      string `json:"purl,omitempty"`
	Message   string `json:"message,omitempty"`
}
