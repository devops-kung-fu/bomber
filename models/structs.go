package models

import "time"

type Package struct {
	Purl            string          `json:"coordinates"`
	Reference       string          `json:"reference,omitempty"`
	Description     string          `json:"description,omitempty"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	ID                 string        `json:"id,omitempty"`
	DisplayName        string        `json:"displayName,omitempty"`
	Title              string        `json:"title,omitempty"`
	Description        string        `json:"description,omitempty"`
	CvssScore          float64       `json:"cvssScore,omitempty"`
	CvssVector         string        `json:"cvssVector,omitempty"`
	Cwe                string        `json:"cwe,omitempty"`
	Reference          string        `json:"reference,omitempty"`
	ExternalReferences []interface{} `json:"externalReferences,omitempty"`
	Severity           string        `json:"severity,omitempty"`
}

type Summary struct {
	Unspecified int
	Low         int
	Moderate    int
	High        int
	Critical    int
}

type Results struct {
	Meta     Meta      `json:"meta,omitempty"`
	Summary  Summary   `json:"summary,omitempty"`
	Packages []Package `json:"packages,omitempty"`
}

type Meta struct {
	Generator string    `json:"generator"`
	URL       string    `json:"url"`
	Version   string    `json:"version"`
	Provider  string    `json:"provider"`
	Date      time.Time `json:"date"`
}

type Credentials struct {
	Username string
	Token    string
}

func NewResults(packages []Package, summary Summary, version, providerName string) Results {
	return Results{
		Meta: Meta{
			Generator: "bomber",
			URL:       "https://github.com/devops-kung-fu/bomber",
			Version:   version,
			Provider:  providerName,
			Date:      time.Now(),
		},
		Summary:  summary,
		Packages: packages,
	}
}
