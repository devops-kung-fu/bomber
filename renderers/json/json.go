package json

import (
	"bytes"
	"encoding/json"
	"fmt"
	"log"

	"github.com/devops-kung-fu/bomber/models"
)

type JsonRenderer struct{}

func (JsonRenderer) Render(results models.Results) (err error) {
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

	fmt.Println(string(prettyJSON.Bytes()))
	return
}
