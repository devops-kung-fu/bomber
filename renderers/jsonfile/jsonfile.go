// Package json contains functionality to render output in json format
package jsonfile

import (
	"encoding/json"
	"log"
	"os"

	"github.com/devops-kung-fu/common/util"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render to JSON format
type Renderer struct{}

// Render outputs json to STDOUT
func (Renderer) Render(results models.Results) error {
	b, _ := json.MarshalIndent(results, "", "\t")
	filename := lib.GenerateFilename("json")
	util.PrintInfo("Writing JSON output:", filename)
	if err := os.WriteFile(filename, b, 0666); err != nil {
		log.Fatal(err)
	}
	return nil
}
