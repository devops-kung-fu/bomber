// Package renderers contains functionality to render output in various formats
package renderers

import (
	"fmt"
	"strings"

	"github.com/devops-kung-fu/bomber/models"
	"github.com/devops-kung-fu/bomber/renderers/ai"
	"github.com/devops-kung-fu/bomber/renderers/html"
	"github.com/devops-kung-fu/bomber/renderers/json"
	"github.com/devops-kung-fu/bomber/renderers/stdout"
)

// NewRenderer will return a Renderer interface for the requested output
func NewRenderer(output string) (renderers []models.Renderer, err error) {
	for _, s := range strings.Split(output, ",") {
		switch s {
		case "stdout":
			renderers = append(renderers, stdout.Renderer{})
		case "json":
			renderers = append(renderers, json.Renderer{})
		case "html":
			renderers = append(renderers, html.Renderer{})
		case "ai":
			renderers = append(renderers, ai.Renderer{})
		default:
			err = fmt.Errorf("%s is not a valid output type", s)
		}
	}
	return
}
