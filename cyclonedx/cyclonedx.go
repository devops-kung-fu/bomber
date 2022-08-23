package cyclonedx

import (
	cyclone "github.com/CycloneDX/cyclonedx-go"
)

func Purls(bom *cyclone.BOM) (purls []string) {
	for _, component := range *bom.Components {
		purls = append(purls, component.PackageURL)
	}
	return
}
