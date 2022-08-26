package models

// Providers defines the methods that a provider must contain
type Provider interface {
	Info() string
	Scan(purls []string, username, token string) (packages []Package, err error)
}
