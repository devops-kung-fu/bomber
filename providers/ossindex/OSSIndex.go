package ossindex

import (
	"encoding/json"
	"log"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const OSSINDEX_URL = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

type CoordinateRequest struct {
	Coordinates []string `json:"coordinates"`
}

func Info() string {
	return "Sonatype OSS Index (https://ossindex.sonatype.org)"
}

func Scan(purls []string, username, token string) (packages []models.Package, err error) {
	j := len(purls)
	for i := 0; i < j; i += 128 {
		z := i + 128
		if z > j {
			z = j
		}
		p := purls[i:z]
		var coordinates CoordinateRequest
		coordinates.Coordinates = append(coordinates.Coordinates, p...)
		req := HttpRequest.NewRequest()
		req.SetBasicAuth(username, token)

		resp, err := req.JSON().Post(OSSINDEX_URL, coordinates)

		defer func() {
			err = resp.Close()
		}()

		log.Printf("OSSIndex Response Status: %v", resp.StatusCode())

		body, err := resp.Body()
		if err != nil {
			return nil, err
		}
		var responses []models.Package
		err = json.Unmarshal(body, &responses)

		packages = append(packages, responses...)
	}
	return
}
