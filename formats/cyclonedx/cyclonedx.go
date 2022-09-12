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

func CycloneDXTestBytes() []byte {
	cycloneDXString := `
	{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"serialNumber": "urn:uuid:2c624d66-de7d-4ad3-b323-4037ff6ce352",
		"version": 1,
		"metadata": {
			"timestamp": "2022-09-06T17:45:39-06:00",
			"tools": [{
				"vendor": "anchore",
				"name": "syft",
				"version": "[not provided]"
			}],
			"component": {
				"bom-ref": "af63bd4c8601b7f1",
				"type": "file",
				"name": "."
			}
		},
		"components": [{
			"bom-ref": "pkg:golang/github.com/cyclonedx/cyclonedx-go@v0.6.0?package-id=135cc8bc545c374",
			"type": "library",
			"name": "github.com/CycloneDX/cyclonedx-go",
			"version": "v0.6.0",
			"cpe": "cpe:2.3:a:CycloneDX:cyclonedx-go:v0.6.0:*:*:*:*:*:*:*",
			"purl": "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0",
			"properties": [{
				"name": "syft:package:metadataType",
				"value": "GolangBinMetadata"
			}]
		}]
	}
	`
	return []byte(cycloneDXString)
}
