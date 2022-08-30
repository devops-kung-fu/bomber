package snyk

import (
	"fmt"
	"log"
	"net/url"

	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/models"
)

const SNYK_URL = "https://api.snyk.io/api/v1/packages/%v/vulnerabilities"

func Info() string {
	return "Snyk (https://snyk.com)"
}

func Scan(purls []string, username, token string) (packages []models.Package, err error) {

	for _, purl := range purls {
		purl = url.QueryEscape(purl)
		url := fmt.Sprintf(SNYK_URL, purl)
		log.Println("Calling API:", url)
		req := HttpRequest.NewRequest()
		req.SetHeaders(map[string]string{"Authorization": fmt.Sprintf("token %v", token)})
		resp, err := req.Get(url)

		defer func() {
			err = resp.Close()
		}()

		log.Printf("Snyk Response Status: %v", resp.StatusCode())

		body, err := resp.Body()
		if err != nil {
			return nil, err
		}
		log.Println(body)
		// var responses []models.Package
		// err = json.Unmarshal(body, &responses)

		// packages = append(packages, responses...)
	}
	return
}
