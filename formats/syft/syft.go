// Package syft provides functionality and structs to work with syft formatted SBOMs
package syft

// BOM represents a Syft Software Bill of Materials
type BOM struct {
	Artifacts []Artifact `json:"artifacts"`
	Schema    Schema     `json:"schema"`
}

// Artifact represents a component/package
type Artifact struct {
	ID           string        `json:"id"`
	Name         string        `json:"name"`
	Version      string        `json:"version"`
	Type         string        `json:"type"`
	FoundBy      string        `json:"foundBy"`
	Locations    []Location    `json:"locations"`
	Licenses     []interface{} `json:"licenses"`
	Language     string        `json:"language"`
	Cpes         []string      `json:"cpes"`
	Purl         string        `json:"purl"`
	MetadataType *string       `json:"metadataType,omitempty"`
	Metadata     *Metadata     `json:"metadata,omitempty"`
}

// Location shows where the artifact is found/located
type Location struct {
	Path string `json:"path"`
}

// Metadata describes basic information about the artifact
type Metadata struct {
	GoBuildSettings   map[string]string `json:"goBuildSettings,omitempty"`
	GoCompiledVersion string            `json:"goCompiledVersion"`
	Architecture      string            `json:"architecture"`
	MainModule        string            `json:"mainModule"`
	H1Digest          *string           `json:"h1Digest,omitempty"`
}

// Schema provides detail about what JSON schema the document conforms to. Used by bomber to determine if the SBOM is in Syft format.
type Schema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

// Purls returns a slice of Purls from a Syft formatted SBOM
func (bom *BOM) Purls() (purls []string) {
	for _, artifact := range bom.Artifacts {
		purls = append(purls, artifact.Purl)
	}
	return
}

// Licenses returns a slice of strings that contain all of the licenses found in the SBOM
func (bom *BOM) Licenses() (licenses []string) {
	return
}

// TestBytes creates a byte array containing a Syft document used for testing
func TestBytes() []byte {
	SPDXString := `
		{
			"artifacts": [{
				"id": "135cc8bc545c374",
				"name": "github.com/CycloneDX/cyclonedx-go",
				"version": "v0.6.0",
				"type": "go-module",
				"foundBy": "go-module-binary-cataloger",
				"locations": [{
					"path": "bomber"
				}],
				"licenses": [],
				"language": "go",
				"cpes": [
					"cpe:2.3:a:CycloneDX:cyclonedx-go:v0.6.0:*:*:*:*:*:*:*",
					"cpe:2.3:a:CycloneDX:cyclonedx_go:v0.6.0:*:*:*:*:*:*:*"
				],
				"purl": "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0",
				"metadataType": "GolangBinMetadata",
				"metadata": {
					"goCompiledVersion": "go1.19",
					"architecture": "amd64",
					"h1Digest": "h1:SizWGbZzFTC/O/1yh072XQBMxfvsoWqd//oKCIyzFyE=",
					"mainModule": "github.com/devops-kung-fu/bomber"
				}
			}],
			"schema": {
				"version": "3.3.2",
				"url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-3.3.2.json"
			}
		}`
	return []byte(SPDXString)
}
