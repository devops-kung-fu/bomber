package models

// Provider defines the methods that a provider must contain
type Provider interface {
	Info() string
	Scan(purls []string, credentials *Credentials) (packages []Package, err error)
}

// Renderer defines the methods that a renderer must contain
type Renderer interface {
	Render(results Results) error
}

// Encricher defines methods that can enrich a collection of vulnerabilities
type Enricher interface {
	Enrich(vulnerabilities []Vulnerability) (enriched []Vulnerability, err error)
}
