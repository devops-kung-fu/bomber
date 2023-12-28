// Package json contains functionality to render output in json format
package ai

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render AI HTML output format
type Renderer struct{}

// Render outputs ai generated report
func (Renderer) Render(results models.Results) error {

	fmt.Println("Hello AI")
	return nil
}
