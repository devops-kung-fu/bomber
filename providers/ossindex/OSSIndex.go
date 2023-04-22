// Package ossindex contains functionality to retrieve vulnerability information from Sonatype's OSSINDEX
package ossindex

import (
	"encoding/json"
	"errors"
	"fmt"
	"log"
	"os"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/kirinlabs/HttpRequest"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/models"
)

const ossindexURL = "https://ossindex.sonatype.org/api/v3/authorized/component-report"

// Provider represents the OSSIndex provider
type Provider struct{}

// CoordinateRequest used for the request to the OSSIndex
type CoordinateRequest struct {
	Coordinates []string `json:"coordinates"`
}

func ToVDR(packages []models.Package) (vdr *cyclone.BOM) {
	vdr = cyclone.NewBOM()
	vulnerabilities := make([]cyclone.Vulnerability, 0)
	vdr.Vulnerabilities = &vulnerabilities
	for _, p := range packages {
		if len(p.Vulnerabilities) == 0 {
			continue
		}
		vuln := &cyclone.Vulnerability{
			BOMRef: "",
			// ID:             v.Aliases[0],
			// Source:         &cyclone.Source{Name: "NVD", URL: "https://nvd.nist.gov/vuln/detail/" + v.Aliases[0]},
			// References:     &[]cyclone.VulnerabilityReference{},
			// Ratings:        &[]cyclone.VulnerabilityRating{},
			// CWEs:           CWEStringToInt(v.DatabaseSpecific.CweIDS),
			// Description:    v.Summary,
			// Detail:         v.Details,
			// Recommendation: "",
			// Advisories:     &[]cyclone.Advisory{},
			// Created:        "",
			// Published:      v.Published,
			// Updated:        v.Modified,
			// Credits:        &cyclone.Credits{},
			Tools: &[]cyclone.Tool{
				{
					Vendor:  "DKFM",
					Name:    "bomber (OSSINDEX)",
					Version: "1.0.0", //TODO: Fill this in during render
					Hashes:  &[]cyclone.Hash{},
					ExternalReferences: &[]cyclone.ExternalReference{
						{
							URL:     "https://github.com/devops-kung-fu/bomber",
							Comment: "bomber GitHub repository",
							Hashes:  &[]cyclone.Hash{},
							Type:    "support",
						},
					},
				},
			},
			//TODO: Put this in the command as a flag --analysis
			// Analysis: &cyclone.VulnerabilityAnalysis{ //If someone fills this out, it's a VEX
			// 	State:         "-",
			// 	Justification: "-",
			// 	Response: &[]cyclone.ImpactAnalysisResponse{
			// 		"-",
			// 	},
			// 	Detail: "-",
			// },
			Affects: &[]cyclone.Affects{
				{
					Ref: "purl",
				},
			},
			// Properties: &[]cyclone.Property{},
		}
		*vdr.Vulnerabilities = append(*vdr.Vulnerabilities, *vuln)
	}
	return
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
	vulnerablePackages := []models.Package{}
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
			if err = json.Unmarshal(body, &response); err != nil {
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
					vulnerablePackages = append(vulnerablePackages, response[i])
				}
			}

		} else {
			err = fmt.Errorf("error retrieving vulnerability data (%v)", resp.Response().Status)
			break
		}
	}
	ToVDR(vulnerablePackages)
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
