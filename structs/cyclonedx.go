package structs

//Cyclonedx represents a CycloneDX Software Bill of Materials (1.4 spec)
type Cyclonedx struct {
	BOMFormat    string             `json:"bomFormat"`
	SpecVersion  string             `json:"specVersion"`
	SerialNumber string             `json:"serialNumber"`
	Version      int64              `json:"version"`
	Metadata     Metadata           `json:"metadata"`
	Components   []ComponentElement `json:"components"`
}

type ComponentElement struct {
	Publisher          string              `json:"publisher"`
	Group              string              `json:"group"`
	Name               string              `json:"name"`
	Version            string              `json:"version"`
	Description        string              `json:"description"`
	Scope              *string             `json:"scope,omitempty"`
	Hashes             []Hash              `json:"hashes"`
	Licenses           []PurpleLicense     `json:"licenses"`
	Purl               string              `json:"purl"`
	ExternalReferences []ExternalReference `json:"externalReferences"`
	Type               string              `json:"type"`
	BOMRef             string              `json:"bom-ref"`
}

type ExternalReference struct {
	Type string `json:"type"`
	URL  string `json:"url"`
}

type Hash struct {
	Alg     string `json:"alg"`
	Content string `json:"content"`
}

type PurpleLicense struct {
	License FluffyLicense `json:"license"`
}

type FluffyLicense struct {
	ID string `json:"id"`
}

//Metadata provides additional information about a BOM.
type Metadata struct {
	Timestamp string            `json:"timestamp"`
	Tools     []Tool            `json:"tools"`
	Component MetadataComponent `json:"component"`
}

//MetadataComponent the component that the BOM describes.
type MetadataComponent struct {
	Group    string             `json:"group"`
	Name     string             `json:"name"`
	Version  string             `json:"version"`
	Licenses []TentacledLicense `json:"licenses"`
	Purl     string             `json:"purl"`
	Type     string             `json:"type"`
	BOMRef   string             `json:"bom-ref"`
}

type TentacledLicense struct {
	License StickyLicense `json:"license"`
}

type StickyLicense struct {
	ID  string `json:"id"`
	URL string `json:"url"`
}

type Tool struct {
	Vendor  string `json:"vendor"`
	Name    string `json:"name"`
	Version string `json:"version"`
	Hashes  []Hash `json:"hashes"`
}

func NewCycloneDX() (bom Cyclonedx) {
	return Cyclonedx{}
}
