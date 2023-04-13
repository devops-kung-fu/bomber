// Package ossindex contains functionality to retrieve vulnerability information from Sonatype's OSSINDEX
package ossindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/lib/filters"
	"github.com/devops-kung-fu/bomber/models"
)

const ossindexURL = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

// Provider represents the OSSIndex provider
type Provider struct{}

// CoordinateRequest used for the request to the OSSIndex
type CoordinateRequest struct {
	Coordinates []string `json:"coordinates"`
}

// Info provides basic information about the OSSIndexProvider
func (Provider) Info() string {
	return "Sonatype OSS Index (https://ossindex.sonatype.org)"
}

// Scan scans a slice of Purls for vulnerabilities against the OSS Index
func (Provider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	if err = validateCredentials(credentials); err != nil {
		return nil, fmt.Errorf("could not validate credentials: %w", err)
	}
	purls = filters.Sanitize(purls)
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

		resp, _ := req.JSON().Post(ossindexURL, coordinates)
		defer func() {
			_ = resp.Close()
		}()

		log.Printf("OSSIndex Response Status: %v", resp.StatusCode())
		body, _ := resp.Body()
		if resp.StatusCode() == 200 {
			var response []models.Package
			err = json.Unmarshal(body, &response)
			if err != nil {
				return
			}
			for i, pkg := range response {
				log.Println("Purl:", response[i].Purl)
				for ii := range response[i].Vulnerabilities {
					log.Println(response[i].Vulnerabilities[ii].ID)
					response[i].Vulnerabilities[ii].Severity = lib.Rating(response[i].Vulnerabilities[ii].CvssScore)
				}
				if len(pkg.Vulnerabilities) > 0 {
					packages = append(packages, response[i])
				}
			}
		} else {
			err = fmt.Errorf("error retrieving vulnerability data (%v)", resp.Response().Status)
			break
		}
	}
	return
}

func validateCredentials(credentials *models.Credentials) (err error) {
	if credentials == nil {
		return errors.New("credentials cannot be nil")
	}
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
