package providers

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
	"github.com/devops-kung-fu/bomber/providers/ossindex"
	"github.com/devops-kung-fu/bomber/providers/osv"
	"github.com/devops-kung-fu/bomber/providers/snyk"
)

// NewProvider will return a provider interface for the requested vulnerability services
func NewProvider(name string) (provider models.Provider, err error) {
	switch name {
	case "ossindex":
		provider = ossindex.Provider{}
	case "osv":
		provider = osv.Provider{}
	case "snyk":
		provider = snyk.Provider{}
	default:
		err = fmt.Errorf("%s is not a valid provider type", name)
	}
	return
}
