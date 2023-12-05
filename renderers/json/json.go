// Package json contains functionality to render output in json format
package json

import (
	"encoding/json"
	"fmt"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render to JSON format
type Renderer struct{}

// Render outputs json to STDOUT
func (Renderer) Render(results models.Results) error {
	b, _ := json.MarshalIndent(results, "", "\t")
	fmt.Println(string(b))
	return nil
}
