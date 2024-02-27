// Package ai contains functionality to render output using GenAI
package ai

import (
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render AI HTML output format
type Renderer struct{}

// Render outputs ai generated report
func (Renderer) Render(results models.Results) error {

	//results has a slice of packages, each containing a number of vulnerabilities. For the ai output, the description of the vulnerability
	//in the results needs to be an AI summary of the complete vulnerability. The AI renderer should only print out minimal info + the rendered severity.
	fmt.Println("Hello AI")
	return nil
}
