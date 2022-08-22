package cyclonedx

import (
	cyclone "github.com/CycloneDX/cyclonedx-go"

	"github.com/devops-kung-fu/bomber/spdx"
)

// NewBOM is a convenience method passing through to cyclonedx-go
func NewBOM() *cyclone.BOM {
	bom := cyclone.BOM{}
	return &bom
}

// ToSPDX converts from a CycloneDX BoM to a SPDX BoM
func ToSPDX(bom *cyclone.BOM) *spdx.BOM {
	spdx := spdx.NewBOM()
	return spdx
}

func Purls(bom *cyclone.BOM) (purls []string) {
	b := *bom
	c := *b.Components
	for i := range c {
		component := c[i]
		purls = append(purls, component.PackageURL)
	}
	return
}
