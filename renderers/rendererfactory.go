// Package renderers contains functionality to render output in various formats
package renderers

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
	"github.com/devops-kung-fu/bomber/renderers/html"
	"github.com/devops-kung-fu/bomber/renderers/json"
	"github.com/devops-kung-fu/bomber/renderers/stdout"
)

// NewRenderer will return a Renderer interface for the requested output
func NewRenderer(output string) (renderer models.Renderer, err error) {
	switch output {
	case "stdout":
		renderer = stdout.Renderer{}
	case "json":
		renderer = json.Renderer{}
	case "html":
		renderer = html.Renderer{}
	default:
		err = fmt.Errorf("%s is not a valid output type", output)
	}
	return
}
