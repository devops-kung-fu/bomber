package models

// Provider defines the methods that a provider must contain
type Provider interface {
	SupportedEcosystems() []string
	Info() string
	Scan(purls []string, credentials *Credentials) (packages []Package, err error)
}

// Renderer defines the methods that a renderer must contain
type Renderer interface {
	Render(results Results) error
}

// Enricher defines methods that can enrich a collection of vulnerabilities
type Enricher interface {
	Enrich(vulnerabilities []Vulnerability, credentials *Credentials) (enriched []Vulnerability, err error)
}
