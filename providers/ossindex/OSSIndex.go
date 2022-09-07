package ossindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const OSSINDEX_URL = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

type OSSIndexProvider struct{}

type CoordinateRequest struct {
	Coordinates []string `json:"coordinates"`
}

// Provides basic information about the OSSIndexProvider
func (OSSIndexProvider) Info() string {
	return "Sonatype OSS Index (https://ossindex.sonatype.org)"
}

// Scan scans a slice of Purls for vulnerabilities against the OSS Index
func (OSSIndexProvider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	err = validateCredentials(credentials)
	if err != nil {
		return
	}
	totalPurls := len(purls)
	for startIndex := 0; startIndex < totalPurls; startIndex += 128 {
		endIndex := startIndex + 128
		if endIndex > totalPurls {
			endIndex = totalPurls
		}
		p := purls[startIndex:endIndex]
		var coordinates CoordinateRequest
		coordinates.Coordinates = append(coordinates.Coordinates, p...)
		req := HttpRequest.NewRequest()
		req.SetBasicAuth(credentials.Username, credentials.Token)

		resp, _ := req.JSON().Post(OSSINDEX_URL, coordinates)
		defer func() {
			_ = resp.Close()
		}()

		log.Printf("OSSIndex Response Status: %v", resp.StatusCode())
		body, _ := resp.Body()
		if resp.StatusCode() == 200 {
			var responses []models.Package
			err = json.Unmarshal(body, &responses)
			if err != nil {
				return
			}
			// for _, pkg := range responses {
			// 	for _, vv := rnge pkg.Vulnerabilities {
			// 		log.Println("SEVERITY:", vv.Severity, fmt.Sprintf("%f", vv.CvssScore))
			// 		vv.Severity =
			// 	}
			// }
			packages = append(packages, responses...)
		} else {
			err = fmt.Errorf("error retrieving vulnerability data (%v)", resp.Response().Status)
			break
		}
	}
	return
}

func validateCredentials(credentials *models.Credentials) (err error) {
	if credentials.Username == "" {
		credentials.Username = os.Getenv("BOMBER_PROVIDER_USERNAME")
	}
	if credentials.Token == "" {
		credentials.Token = os.Getenv("BOMBER_PROVIDER_TOKEN")
	}

	if credentials.Username == "" && credentials.Token == "" {
		err = errors.New("bomber requires a username and token to use the OSS Index provider")
	}
	return
}
