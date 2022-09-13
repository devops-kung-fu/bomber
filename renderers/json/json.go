package json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render to JSON format
type Renderer struct{}

// Render renders pretty printed JSON to the STDOUT
func (Renderer) Render(results models.Results) (err error) {
	b, err := json.Marshal(results)
	if err != nil {
		log.Println(err)
		return err
	}

	var prettyJSON bytes.Buffer
	error := json.Indent(&prettyJSON, b, "", "\t")
	if error != nil {
		log.Println("JSON parse error: ", error)
		return err
	}

	fmt.Println(prettyJSON.String())
	return
}
