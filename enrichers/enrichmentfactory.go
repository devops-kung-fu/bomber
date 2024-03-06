// package enrichers are meant to enrich vulnerability data from other sources
package enrichers

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/enrichers/epss"
	"github.com/devops-kung-fu/bomber/models"
)

// NewProvider will return a provider interface for the requested vulnerability services
func NewEnricher(name string) (enricher models.Enricher, err error) {
	switch name {
	case "epss":
		enricher = epss.Enricher{}
	default:

		err = fmt.Errorf("%s is not a valid provider type", name)
	}
	return
}
