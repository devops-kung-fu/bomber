// Package ossindex contains functionality to retrieve vulnerability information from Sonatype's OSSINDEX
package ossindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/go-resty/resty/v2"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/models"
)

const ossindexURL = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

var client *resty.Client

func init() {
	// Cloning the transport ensures a proper working http client that respects the proxy settings
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSHandshakeTimeout = 60 * time.Second
	client = resty.New().SetTransport(transport)
}

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
	totalPurls := len(purls)
	for startIndex := 0; startIndex < totalPurls; startIndex += 128 {
		endIndex := startIndex + 128
		if endIndex > totalPurls {
			endIndex = totalPurls
		}
		p := purls[startIndex:endIndex]
		var coordinates CoordinateRequest
		coordinates.Coordinates = append(coordinates.Coordinates, p...)

		resp, _ := client.R().
			SetBody(coordinates).
			SetBasicAuth(credentials.Username, credentials.ProviderToken).
			Post(ossindexURL)

		if resp.StatusCode() == http.StatusOK {
			var response []models.Package
			if err := json.Unmarshal(resp.Body(), &response); err != nil {
				log.Println("Error:", err)
				return nil, err
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
			log.Println("Error: unexpected status code. Skipping the batch: ", string(resp.Body()))
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

	if credentials.ProviderToken == "" {
		credentials.ProviderToken = os.Getenv("BOMBER_PROVIDER_TOKEN")
	}

	if credentials.Username == "" && credentials.ProviderToken == "" {
		err = errors.New("bomber requires a username and token to use the OSS Index provider")
	}
	return
}
