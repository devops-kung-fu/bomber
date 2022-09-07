package providers

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
	"github.com/devops-kung-fu/bomber/providers/ossindex"
	"github.com/devops-kung-fu/bomber/providers/osv"
)

func NewProvider(name string) (provider models.Provider, err error) {
	switch name {
	case "ossindex":
		provider = ossindex.OSSIndexProvider{}
	case "osv":
		provider = osv.OSVProvider{}
	default:
		err = fmt.Errorf("%s is not a valid provider type", name)
	}
	return
}
