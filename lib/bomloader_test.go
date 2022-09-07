package lib

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func Test_removeDuplicates(t *testing.T) {
	test := []string{"A", "B", "C", "D"}

	result := removeDuplicates(test)
	assert.Len(t, result, 4)

	test = append(test, "B")
	result = removeDuplicates(test)
	assert.Len(t, result, 4)
}

func TestLoad(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("test-cyclonedx.json", cycloneDXTestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("./")
	assert.Len(t, files, 1)
	_, err = Load(afs, []string{"/"})
	assert.NoError(t, err)
}

func cycloneDXTestBytes() []byte {
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

func spdxTestBytes() []byte {
	spdxString := `
	
	`
	return []byte(spdxString)
}
