package syft

// BOM represents a Syft Software Bill of Materials
type BOM struct {
	Artifacts             []Artifact    `json:"artifacts"`
	ArtifactRelationships []interface{} `json:"artifactRelationships"`
	Source                Source        `json:"source"`
	Distro                Distro        `json:"distro"`
	Descriptor            Descriptor    `json:"descriptor"`
	Schema                Schema        `json:"schema"`
}

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

type Location struct {
	Path string `json:"path"`
}

type Metadata struct {
	GoBuildSettings   map[string]string `json:"goBuildSettings,omitempty"`
	GoCompiledVersion string            `json:"goCompiledVersion"`
	Architecture      string            `json:"architecture"`
	MainModule        string            `json:"mainModule"`
	H1Digest          *string           `json:"h1Digest,omitempty"`
}

type Descriptor struct {
	Name          string        `json:"name"`
	Version       string        `json:"version"`
	Configuration Configuration `json:"configuration"`
}

type Configuration struct {
	ConfigPath         string             `json:"configPath"`
	Verbosity          int64              `json:"verbosity"`
	Quiet              bool               `json:"quiet"`
	Output             []string           `json:"output"`
	OutputTemplatePath string             `json:"output-template-path"`
	File               string             `json:"file"`
	CheckForAppUpdate  bool               `json:"check-for-app-update"`
	Anchore            Anchore            `json:"anchore"`
	Dev                Dev                `json:"dev"`
	Log                Log                `json:"log"`
	Catalogers         interface{}        `json:"catalogers"`
	Package            Package            `json:"package"`
	FileMetadata       FileMetadata       `json:"file-metadata"`
	FileClassification FileClassification `json:"file-classification"`
	FileContents       FileContents       `json:"file-contents"`
	Secrets            Secrets            `json:"secrets"`
	Registry           Registry           `json:"registry"`
	Exclude            []interface{}      `json:"exclude"`
	Attest             Attest             `json:"attest"`
	Platform           string             `json:"platform"`
}

type Anchore struct {
	Host                   string `json:"host"`
	Path                   string `json:"path"`
	Dockerfile             string `json:"dockerfile"`
	OverwriteExistingImage bool   `json:"overwrite-existing-image"`
	ImportTimeout          int64  `json:"import-timeout"`
}

type Attest struct {
	Key                 string `json:"key"`
	CERT                string `json:"cert"`
	NoUpload            bool   `json:"noUpload"`
	Force               bool   `json:"force"`
	Recursive           bool   `json:"recursive"`
	Replace             bool   `json:"replace"`
	FulcioURL           string `json:"fulcioUrl"`
	FulcioIdentityToken string `json:"fulcio_identity_token"`
	InsecureSkipVerify  bool   `json:"insecure_skip_verify"`
	RekorURL            string `json:"rekorUrl"`
	OidcIssuer          string `json:"oidcIssuer"`
	OidcClientID        string `json:"oidcClientId"`
	OIDCRedirectURL     string `json:"OIDCRedirectURL"`
}

type Dev struct {
	ProfileCPU bool `json:"profile-cpu"`
	ProfileMem bool `json:"profile-mem"`
}

type FileClassification struct {
	Cataloger Cataloger `json:"cataloger"`
}

type Cataloger struct {
	Enabled bool   `json:"enabled"`
	Scope   string `json:"scope"`
}

type FileContents struct {
	Cataloger          Cataloger     `json:"cataloger"`
	SkipFilesAboveSize int64         `json:"skip-files-above-size"`
	Globs              []interface{} `json:"globs"`
}

type FileMetadata struct {
	Cataloger Cataloger `json:"cataloger"`
	Digests   []string  `json:"digests"`
}

type Log struct {
	Structured   bool   `json:"structured"`
	Level        string `json:"level"`
	FileLocation string `json:"file-location"`
}

type Package struct {
	Cataloger               Cataloger `json:"cataloger"`
	SearchUnindexedArchives bool      `json:"search-unindexed-archives"`
	SearchIndexedArchives   bool      `json:"search-indexed-archives"`
}

type Registry struct {
	InsecureSkipTLSVerify bool          `json:"insecure-skip-tls-verify"`
	InsecureUseHTTP       bool          `json:"insecure-use-http"`
	Auth                  []interface{} `json:"auth"`
}

type Secrets struct {
	Cataloger           Cataloger     `json:"cataloger"`
	AdditionalPatterns  Distro        `json:"additional-patterns"`
	ExcludePatternNames []interface{} `json:"exclude-pattern-names"`
	RevealValues        bool          `json:"reveal-values"`
	SkipFilesAboveSize  int64         `json:"skip-files-above-size"`
}

type Distro struct {
}

type Schema struct {
	Version string `json:"version"`
	URL     string `json:"url"`
}

type Source struct {
	Type   string `json:"type"`
	Target string `json:"target"`
}

// Purls returns a slice of Purls from a Syft formatted SBOM
func (bom *BOM) Purls() (purls []string) {
	for _, artifact := range bom.Artifacts {
		purls = append(purls, artifact.Purl)
	}
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
			"artifactRelationships": [],
			"source": {
				"type": "directory",
				"target": "."
			},
			"distro": {},
			"descriptor": {
				"name": "syft",
				"version": "[not provided]",
				"configuration": {
					"configPath": "",
					"verbosity": 0,
					"quiet": false,
					"output": [
						"json=sbom/bomber.syft.json",
						"spdx-json=sbom/bomber.spdx.json",
						"cyclonedx-json=sbom/bomber.cyclonedx.json"
					],
					"output-template-path": "",
					"file": "",
					"check-for-app-update": true,
					"anchore": {
						"host": "",
						"path": "",
						"dockerfile": "",
						"overwrite-existing-image": false,
						"import-timeout": 30
					},
					"dev": {
						"profile-cpu": false,
						"profile-mem": false
					},
					"log": {
						"structured": false,
						"level": "warning",
						"file-location": ""
					},
					"catalogers": null,
					"package": {
						"cataloger": {
							"enabled": true,
							"scope": "Squashed"
						},
						"search-unindexed-archives": false,
						"search-indexed-archives": true
					},
					"file-metadata": {
						"cataloger": {
							"enabled": false,
							"scope": "Squashed"
						},
						"digests": [
							"sha256"
						]
					},
					"file-classification": {
						"cataloger": {
							"enabled": false,
							"scope": "Squashed"
						}
					},
					"file-contents": {
						"cataloger": {
							"enabled": false,
							"scope": "Squashed"
						},
						"skip-files-above-size": 1048576,
						"globs": []
					},
					"secrets": {
						"cataloger": {
							"enabled": false,
							"scope": "AllLayers"
						},
						"additional-patterns": {},
						"exclude-pattern-names": [],
						"reveal-values": false,
						"skip-files-above-size": 1048576
					},
					"registry": {
						"insecure-skip-tls-verify": false,
						"insecure-use-http": false,
						"auth": []
					},
					"exclude": [],
					"attest": {
						"key": "",
						"cert": "",
						"noUpload": false,
						"force": false,
						"recursive": false,
						"replace": false,
						"fulcioUrl": "https://fulcio.sigstore.dev",
						"fulcio_identity_token": "",
						"insecure_skip_verify": false,
						"rekorUrl": "https://rekor.sigstore.dev",
						"oidcIssuer": "https://oauth2.sigstore.dev/auth",
						"oidcClientId": "sigstore",
						"OIDCRedirectURL": ""
					},
					"platform": "",
					"external_sources": {
						"external-sources-enabled": false
					}
				}
			},
			"schema": {
				"version": "3.3.2",
				"url": "https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-3.3.2.json"
			}
		}`
	return []byte(SPDXString)
}
