package lib

import (
	"fmt"
	"log"
	"os"
	"slices"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/devops-kung-fu/common/util"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/afero"

	"github.com/devops-kung-fu/bomber/lib/enrichment"
	"github.com/devops-kung-fu/bomber/lib/filters"
	"github.com/devops-kung-fu/bomber/models"
)

// Scanner encapsulates the properties needed to scan a file for vulnerabilities
type Scanner struct {
	SeveritySummary models.Summary
	Credentials     models.Credentials
	Renderer        models.Renderer
	Provider        models.Provider
	IgnoreFile      string
	Severity        string
	ExitCode        bool
	Output          string
	ProviderName    string
	Version         string
}

// Scan scans a file for vulnerabilities and renders it to the selected output
func (s *Scanner) Scan(afs *afero.Afero, args []string) (err error) {
	scanned, purls, licenses, err := Load(afs, args)
	if err != nil {
		log.Print(err)
		return
	}
	if len(purls) > 0 {
		var response []models.Package

		ecosystems := []string{}
		for _, p := range purls {
			purl, err := packageurl.FromString(p)
			if err != nil {
				util.PrintErr(err)
			}
			if !slices.Contains(ecosystems, purl.Type) {
				ecosystems = append(ecosystems, purl.Type)
			}
		}
		spinner := spinner.New(spinner.CharSets[9], 100*time.Millisecond)

		purls, issues := filters.Sanitize(purls)

		util.DoIf(s.Output != "json", func() {
			util.PrintInfo("Ecosystems detected:", strings.Join(ecosystems, ","))

			//for each models.Issue in issues, write a message to the console
			for _, issue := range issues {
				util.PrintWarningf("%v (%v)\n", issue.Message, issue.Purl)
			}

			util.PrintInfof("Scanning %v packages for vulnerabilities...\n", len(purls))
			util.PrintInfo("Vulnerability Provider:", s.Provider.Info(), "\n")
			if s.Severity != "" {
				util.PrintInfof("Showing vulnerabilities with a severity of %s or higher", strings.ToUpper(s.Severity))
				fmt.Println()
			}

			spinner.Suffix = fmt.Sprintf(" Fetching vulnerability data from %s", s.ProviderName)
			spinner.Start()
		})

		response, err := s.Provider.Scan(purls, &s.Credentials)
		if err != nil {
			log.Print(err)
		}
		var ignoredCVE []string
		if s.IgnoreFile != "" {
			ignoredCVE, err = LoadIgnore(afs, s.IgnoreFile)
			if err != nil {
				util.PrintWarningf("Ignore flag set, but there was an error: %s", err)
			}
		}

		//Get rid of the packages that have a vulnerability lower than its fail severity
		if s.Severity != "" {
			for i, p := range response {
				vulns := []models.Vulnerability{}
				for _, v := range p.Vulnerabilities {
					// severity flag passed in
					fs := ParseSeverity(s.Severity)
					// severity of vulnerability
					vs := ParseSeverity(v.Severity)
					if vs >= fs {
						vulns = append(vulns, v)
					} else {
						log.Printf("Removed vulnerability that was %s when the filter was %s", v.Severity, s.Severity)
					}
				}
				log.Printf("Filtered out %d vulnerabilities for package %s", len(p.Vulnerabilities)-len(vulns), p.Purl)
				response[i].Vulnerabilities = vulns
			}
		}

		for i, p := range response {
			enrichedVulnerabilities, _ := enrichment.Enrich(p.Vulnerabilities)
			response[i].Vulnerabilities = enrichedVulnerabilities

			if len(ignoredCVE) > 0 {
				filteredVulnerabilities := filters.Ignore(p.Vulnerabilities, ignoredCVE)
				response[i].Vulnerabilities = filteredVulnerabilities
			}
		}

		util.DoIf(s.Output != "json", func() {
			spinner.Stop()
		})
		if err != nil {
			util.PrintErr(err)
			os.Exit(1)
		}
		vulnCount := 0
		for _, r := range response {
			vulnCount += len(r.Vulnerabilities)
			for _, v := range r.Vulnerabilities {
				AdjustSummary(v.Severity, &s.SeveritySummary)
			}
		}
		results := models.NewResults(response, s.SeveritySummary, scanned, licenses, s.Version, s.ProviderName)
		if err = s.Renderer.Render(results); err != nil {
			log.Println(err)
		}
		if s.ExitCode {
			code := HighestSeverityExitCode(FlattenVulnerabilities(results.Packages))
			log.Printf("fail severity: %d", code)
			os.Exit(code)
		}
	} else {
		util.PrintInfo("No packages were detected. Nothing has been scanned.")
	}
	return
}
