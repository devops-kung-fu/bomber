package spdx

// BOM represents a SPDX Software Bill of Materials
type BOM struct {
	SPDXVersion         string         `json:"spdxVersion"`
	DataLicense         string         `json:"dataLicense"`
	SPDXID              string         `json:"SPDXID"`
	DocumentName        string         `json:"documentName"`
	DocumentNamespace   string         `json:"documentNamespace"`
	ExternalDocumentRef string         `json:"externalDocumentRef,omitempty"`
	DocumentComment     string         `json:"documentComment,omitempty"`
	Packages            []Package      `json:"packages"`
	Files               []File         `json:"files,omitempty"`
	Relationships       []Relationship `json:"relationships,omitempty"`
}

// Package represents a component/package
type Package struct {
	Name                    string `json:"name,omitempty"`
	SPDXID                  string `json:"SPDXID,omitempty"`
	VersionInfo             string `json:"versionInfo,omitempty"`
	PackageFileName         string `json:"packageFileName,omitempty"`
	Supplier                string `json:"supplier,omitempty"`
	Originator              string `json:"originator,omitempty"`
	DownloadLocation        string `json:"downloadLocation,omitempty"`
	FilesAnalyzed           bool   `json:"filesAnalyzed,omitempty"`
	PackageVerificationCode struct {
		PackageVerificationCodeValue        string `json:"packageVerificationCodeValue,omitempty"`
		PackageVerificationCodeExcludedFile string `json:"packageVerificationCodeExcludedFile,omitempty"`
	} `json:"packageVerificationCode,omitempty"`
	Checksum             Checksum      `json:"checksum,omitempty"`
	Homepage             string        `json:"homepage,omitempty"`
	SourceInfo           string        `json:"sourceInfo,omitempty"`
	LicenseConcluded     string        `json:"licenseConcluded,omitempty"`
	LicenseInfoFromFiles []string      `json:"licenseInfoFromFiles,omitempty"`
	LicenseDeclared      []string      `json:"licenseDeclared,omitempty"`
	CopyrightText        string        `json:"copyrightText,omitempty"`
	Summary              string        `json:"summary,omitempty"`
	Description          string        `json:"description,omitempty"`
	Comment              string        `json:"comment,omitempty"`
	ExternalRefs         []ExternalRef `json:"externalRefs,omitempty"`
	AttributionText      string        `json:"attributionText,omitempty"`
}

// ExternalRef encapsulates various references such as a Purl. Wonky.
type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory,omitempty"`
	ReferenceType     string `json:"referenceType,omitempty"`
	ReferenceLocator  string `json:"referenceLocator,omitempty"`
	Comment           string `json:"comment,omitempty"`
}

// Checksum is used as a checksum on a package
type Checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

// File represents a scanned file, its licenses, and it'c checksum
type File struct {
	SPDXID             string     `json:"SPDXID"`
	Checksums          []Checksum `json:"checksums"`
	CopyrightText      string     `json:"copyrightText"`
	FileName           string     `json:"fileName"`
	FileTypes          []string   `json:"fileTypes"`
	LicenseConcluded   string     `json:"licenseConcluded"`
	LicenseInfoInFiles []string   `json:"licenseInfoInFiles"`
}

// Relationship encapsulates a relationship from one SPDX element to another. Wonky.
type Relationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

// Purls returns a slice of Purls from a SPDX formatted SBOM
func (bom *BOM) Purls() (purls []string) {
	for _, pkg := range bom.Packages {
		for _, extRef := range pkg.ExternalRefs {
			if extRef.ReferenceType == "purl" {
				purls = append(purls, extRef.ReferenceLocator)
			}
		}
	}
	return
}

// Licenses returns a slice of strings that contain all of the licenses found in the SBOM
func (bom *BOM) Licenses() (licenses []string) {

	return
}

// TestBytes creates a byte array containing a SPDX document used for testing
func TestBytes() []byte {
	SPDXString := `
	{
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": ".",
		"spdxVersion": "SPDX-2.2",
		"creationInfo": {
			"created": "2022-09-07T20:21:50.107518Z",
			"creators": [
				"Organization: Anchore, Inc",
				"Tool: syft-[not provided]"
			],
			"licenseListVersion": "3.18"
		},
		"dataLicense": "CC0-1.0",
		"documentNamespace": "https://anchore.com/syft/dir/c29b2f20-5544-4f7b-9b70-3f44d5df98d2",
		"packages": [{
			"SPDXID": "SPDXRef-135cc8bc545c374",
			"name": "github.com/CycloneDX/cyclonedx-go",
			"licenseConcluded": "NONE",
			"downloadLocation": "NOASSERTION",
			"externalRefs": [{
				"referenceCategory": "PACKAGE_MANAGER",
				"referenceLocator": "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0",
				"referenceType": "purl"
			}]
		}]
	}`
	return []byte(SPDXString)
}
