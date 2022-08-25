package models

type Provider interface {
	Info() string
	Scan(purls []string, username, token string) (coordinateResponses []Package, err error)
}
