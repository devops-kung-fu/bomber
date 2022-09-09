package models

// Providers defines the methods that a provider must contain
type Provider interface {
	Info() string
	Scan(purls []string, credentials *Credentials) (packages []Package, err error)
}

type Renderer interface {
	Render(results Results) error
}
