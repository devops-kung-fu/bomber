package models

import "time"

type Package struct {
	Purl            string          `json:"coordinates"`
	Reference       string          `json:"reference"`
	Description     string          `json:"description"`
	Vulnerabilities []Vulnerability `json:"vulnerabilities"`
}

type Vulnerability struct {
	ID                 string        `json:"id"`
	DisplayName        string        `json:"displayName"`
	Title              string        `json:"title"`
	Description        string        `json:"description"`
	CvssScore          float64       `json:"cvssScore"`
	CvssVector         string        `json:"cvssVector"`
	Cwe                string        `json:"cwe"`
	Reference          string        `json:"reference"`
	ExternalReferences []interface{} `json:"externalReferences"`
	Severity           string        `json:"severity"`
}

type Summary struct {
	None     int
	Low      int
	Moderate int
	High     int
	Critical int
}

type Bomber struct {
	Meta     Meta
	Summary  Summary
	Packages []Package
}

type Meta struct {
	Version string
	Date    time.Time
}
