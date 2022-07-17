package spdx

import (
	"log"

	cyclone "github.com/CycloneDX/cyclonedx-go"
)

//SPDX represents a SPDX Software Bill of Materials
type BOM struct {
	SPDXVersion         string `json:"spdxVersion"`
	DataLicense         string `json:"dataLicense"`
	SPDXID              string `json:"SPDXID"`
	DocumentName        string `json:"documentName"`
	DocumentNamespace   string `json:"documentNamespace"`
	ExternalDocumentRef string `json:"externalDocumentRef,omitempty"`
	CreationInfo        struct {
		LicenseListVersion string `json:"licenseListVersion,omitempty"`
		Person             string `json:"person,omitempty"`
		Organization       string `json:"organization,omitempty"`
		Tool               string `json:"tool,omitempty"`
		Created            string `json:"created"`
		CreatorComment     string `json:"creatorComment,omitempty"`
	} `json:"creationInfo"`
	DocumentComment string         `json:"documentComment,omitempty"`
	Packages        []Package      `json:"packages"`
	Files           []File         `json:"files,omitempty"`
	Relationships   []Relationship `json:"relationships,omitempty"`
}

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
	ExternalRef          []ExternalRef `json:"externalRef,omitempty"`
	AttributionText      string        `json:"attributionText,omitempty"`
}

type ExternalRef struct {
	ReferenceCategory string `json:"referenceCategory,omitempty"`
	ReferenceType     string `json:"referenceType,omitempty"`
	ReferenceLocator  string `json:"referenceLocator,omitempty"`
	Comment           string `json:"comment,omitempty"`
}

type Checksum struct {
	Algorithm     string `json:"algorithm"`
	ChecksumValue string `json:"checksumValue"`
}

type File struct {
	SPDXID             string     `json:"SPDXID"`
	Checksums          []Checksum `json:"checksums"`
	CopyrightText      string     `json:"copyrightText"`
	FileName           string     `json:"fileName"`
	FileTypes          []string   `json:"fileTypes"`
	LicenseConcluded   string     `json:"licenseConcluded"`
	LicenseInfoInFiles []string   `json:"licenseInfoInFiles"`
}

type Relationship struct {
	SpdxElementID      string `json:"spdxElementId"`
	RelatedSpdxElement string `json:"relatedSpdxElement"`
	RelationshipType   string `json:"relationshipType"`
}

//NewBOM creates a new SPDX bom
func NewBOM() *BOM {
	bom := BOM{}
	return &bom
}

//ToCycloneDX converts from a SPDX BoM to a CycloneDX BoM
func ToCycloneDX(bom *BOM) *cyclone.BOM {
	cyclonedx := cyclone.NewBOM()
	log.Printf("Processing SPDX BOM. Name: %s , Spec %s", bom.DocumentName, bom.SPDXVersion)
	return cyclonedx
}
