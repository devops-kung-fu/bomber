package snyk

type JsonApi struct {
	// Version of the JSON API specification this server supports.
	Version string `json:"version"`
}

type LinkProperty interface{}

type Links struct {
	PaginatedLinks
	Related *LinkProperty `json:"related,omitempty"`
}

type PaginatedLinks struct {
	First *LinkProperty `json:"first,omitempty"`
	Last  *LinkProperty `json:"last,omitempty"`
	Next  *LinkProperty `json:"next,omitempty"`
	Prev  *LinkProperty `json:"prev,omitempty"`
	Self  *LinkProperty `json:"self,omitempty"`
}

// Free-form object that may contain non-standard information.
type Meta struct {
	AdditionalProperties map[string]interface{} `json:"-"`
}

type PackageMeta struct {
	// The package’s name
	Name string `json:"name,omitempty"`

	// A name prefix, such as a maven group id or docker image owner
	Namespace string `json:"namespace,omitempty"`

	// The package type or protocol
	Type string `json:"type,omitempty"`

	// The purl of the package
	Url string `json:"url,omitempty"`

	// The version of the package
	Version string `json:"version,omitempty"`
}
