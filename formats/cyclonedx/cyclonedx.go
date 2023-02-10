// Package cyclonedx provides additional functionality to interact with CycloneDX formatted SBOMs
package cyclonedx

import (
	cyclone "github.com/CycloneDX/cyclonedx-go"
)

// Purls returns a slice of Purls from a CycloneDX formatted SBOM
func Purls(bom *cyclone.BOM) (purls []string) {
	for _, component := range *bom.Components {
		purls = append(purls, component.PackageURL)
	}
	return
}

// Licenses returns a slice of strings that contain all of the licenses found in the SBOM
func Licenses(bom *cyclone.BOM) (licenses []string) {
	for _, component := range *bom.Components {
		if component.Licenses != nil {
			for _, licenseChoice := range *component.Licenses {
				if licenseChoice.Expression != "" {
					licenses = append(licenses, licenseChoice.Expression)
				}
				if licenseChoice.License != nil && licenseChoice.License.ID != "" {
					licenses = append(licenses, licenseChoice.License.ID)
				}
			}
		}
	}
	return
}

// TestBytes creates a byte array containing a CycloneDX document used for testing
func TestBytes() []byte {
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
			"licenses": [
				{
					"license": {
						"id": "MIT"
					}
				},
				{
					"expression": "(AFL-2.1 OR BSD-3-Clause)"
				}    
			],
			"properties": [{
				"name": "syft:package:metadataType",
				"value": "GolangBinMetadata"
			}]
		}]
	}
	`
	return []byte(cycloneDXString)
}
