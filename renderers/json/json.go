package json

import (
	"encoding/json"
	"fmt"
	"log"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render to JSON format
type Renderer struct{}

// Render outputs json to STDOUT
func (Renderer) Render(results models.Results) error {
	b, err := json.MarshalIndent(results, "", "\t")
	if err != nil {
		log.Println(err)
		return err
	}

	fmt.Println(string(b))
	return nil
}
