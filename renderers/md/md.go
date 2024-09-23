package md

import (
	"fmt"
	"log"
	"math"
	"path/filepath"
	"strconv"
	"strings"
	"text/template"
	"time"

	"github.com/devops-kung-fu/common/util"
	"github.com/spf13/afero"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render results to a Markdown file
type Renderer struct{}

// Render renders results to a Markdown file
func (Renderer) Render(results models.Results) error {
	var afs *afero.Afero

	if results.Meta.Provider == "test" {
		afs = &afero.Afero{Fs: afero.NewMemMapFs()}
	} else {
		afs = &afero.Afero{Fs: afero.NewOsFs()}
	}

	filename := generateFilename()
	util.PrintInfo("Writing filename:", filename)

	err := writeTemplate(afs, filename, results)

	return err
}

// generateFilename generates a unique filename based on the current timestamp
// in the format "2006-01-02 15:04:05" and replaces certain characters to
// create a valid filename. The resulting filename is a combination of the
// timestamp and a fixed suffix.
func generateFilename() string {
	t := time.Now()
	r := strings.NewReplacer("-", "", " ", "-", ":", "-")
	return filepath.Join(".", fmt.Sprintf("%s-bomber-results.md", r.Replace(t.Format("2006-01-02 15:04:05"))))
}

// writeTemplate writes the results to a file with the specified filename,
// using the given Afero filesystem interface. It creates the file, processes
// percentiles in the results and writes the templated results to the file.
// It also sets file permissions to 0777.
func writeTemplate(afs *afero.Afero, filename string, results models.Results) error {
	processPercentiles(results)

	file, err := afs.Create(filename)
	if err != nil {
		log.Println(err)
		return err
	}

	template := genTemplate("output")
	err = template.ExecuteTemplate(file, "output", results)
	if err != nil {
		log.Println(err)
		return err
	}

	err = afs.Fs.Chmod(filename, 0777)

	return err
}

// processPercentiles calculates and updates the percentile values for
// vulnerabilities in the given results. It converts the percentile from
// a decimal to a percentage and updates the results in place.
func processPercentiles(results models.Results) {
	for i, p := range results.Packages {
		for vi, v := range p.Vulnerabilities {
			per, err := strconv.ParseFloat(v.Epss.Percentile, 64)
			if err != nil {
				log.Println(err)
			} else {
				percentage := math.Round(per * 100)
				if percentage > 0 {
					results.Packages[i].Vulnerabilities[vi].Epss.Percentile = fmt.Sprintf("%d%%", uint64(percentage))
				} else {
					results.Packages[i].Vulnerabilities[vi].Epss.Percentile = "N/A"
				}
			}
		}
	}
}

func genTemplate(output string) (t *template.Template) {

	content := `
![IMG](https://raw.githubusercontent.com/devops-kung-fu/bomber/main/img/bomber-readme-logo.png)

The following results were detected by `+ "`{{.Meta.Generator}} {{.Meta.Version}}`" + ` on {{.Meta.Date}} using the {{.Meta.Provider}} provider.
{{ if ne (len .Packages) 0 }} 

Vulnerabilities displayed may differ from provider to provider. This list may not contain all possible vulnerabilities. Please try the other providers that ` + "`bomber`" + ` supports (osv, github, ossindex, snyk). There is no guarantee that the next time you scan for vulnerabilities that there won't be more, or less of them. Threats are continuous.

EPSS Percentage indicates the % chance that the vulnerability will be exploited. This value will assist in prioritizing remediation. For more information on EPSS, refer to [https://www.first.org/epss/](https://www.first.org/epss/)
{{ else }}
No vulnerabilities found!
{{ end }}

{{ if ne (len .Files) 0 }} 
## Scanned Files

{{ range .Files }}**{{ .Name }}** (sha256:{{ .SHA256 }}){{ end }}
{{end}}
{{ if ne (len .Licenses) 0 }} 
## Licenses

The following licenses were found by ` + "`bomber`" + `:
{{ range $license := .Licenses }}
- {{ $license }}{{ end }}
{{ else }}
**No license information detected.**
{{ end }}

{{ if ne (len .Packages) 0 }} 
## Vulnerability Summary

{{ if ne (len .Meta.SeverityFilter) 0 }}
Only showing vulnerabilities with a severity of ***{{ .Meta.SeverityFilter }}*** or higher.

{{ end }}
| Severity | Count |
| --- | --- |{{ if gt .Summary.Critical 0 }}
| Critical | {{ .Summary.Critical }} |{{ end }}{{ if gt .Summary.High 0 }}
| High | {{ .Summary.High }} |{{ end }}{{ if gt .Summary.Moderate 0 }}
| Moderate | {{ .Summary.Moderate }} |{{ end }}{{ if gt .Summary.Low 0 }}
| Low | {{ .Summary.Low }} |{{ end }}{{ if gt .Summary.Unspecified 0 }}
| Unspecified | {{ .Summary.Unspecified }} |{{ end }}

## Vulnerability Details

{{ range .Packages }}
### {{ .Purl }}
{{if .Description }}{{ .Description }}{{ end }}
#### Vulnerabilities

{{ range .Vulnerabilities }}
{{ if .Title }}Title: **{{ .Title }}**<br>{{ end }}
Severity: **{{ .Severity }}**<br>
{{ if ne (len .Epss.Percentile) 0 }} EPSS: {{ .Epss.Percentile }}<br>{{ end }}
[Reference Documentation]({{ .Reference }})

{{ .Description }}

<hr>

{{ end }}

{{ end }}
{{ end }}

<sub>Powered by the [DevOps Kung Fu Mafia](https://github.com/devops-kung-fu)</sub>
`
	return template.Must(template.New(output).Parse(content))
}
