// Package lib contains core functionality to load Software Bill of Materials and contains common functions
package lib

import (
	"fmt"
	"log"
	"slices"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/devops-kung-fu/common/util"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/afero"

	"github.com/devops-kung-fu/bomber/enrichers"
	"github.com/devops-kung-fu/bomber/filters"
	"github.com/devops-kung-fu/bomber/models"
)

// Scanner represents a vulnerability scanner.
type Scanner struct {
	SeveritySummary models.Summary
	Credentials     models.Credentials
	Renderers       []models.Renderer
	Provider        models.Provider
	Enrichment      []string
	IgnoreFile      string
	Severity        string
	ExitCode        bool
	Output          string
	ProviderName    string
	Version         string
	Afs             *afero.Afero
}

var loader Loader

// Scan performs the vulnerability scan.
func (s *Scanner) Scan(args []string) (exitCode int, err error) {
	loader = Loader{
		s.Afs,
	}
	// Load packages and associated data
	scanned, purls, licenses, err := loader.Load(args)
	if err != nil {
		log.Print(err)
		return
	}
	if slices.Contains(s.Enrichment, "openai") {
		util.PrintWarning("OpenAI enrichment is experimental and may increase scanning time significantly")
	}
	if len(scanned) > 0 {
		if s.Output != "json" {
			util.PrintInfo("Scanning Files:")
			for _, f := range scanned {
				util.PrintTabbed(f.Name)
			}
		}
	}

	// If no packages are detected, print a message and return
	if len(purls) == 0 {
		util.PrintInfo("No packages were detected. Nothing has been scanned.")
		return
	}

	// Perform the package scan
	response, err := s.scanPackages(purls)
	if err != nil {
		return 1, err
	}

	// Process and output the scan results
	return s.processResults(scanned, licenses, response), nil
}

// scanPackages performs the core logic of scanning packages.
func (s *Scanner) scanPackages(purls []string) (response []models.Package, err error) {
	// Detect and print information about ecosystems
	ecosystems := s.detectEcosystems(purls)
	spinner := spinner.New(spinner.CharSets[11], 100*time.Millisecond)

	// Sanitize package URLs and handle initial console output
	purls, issues := filters.Sanitize(purls)
	s.printHeader(len(purls), ecosystems, issues, spinner)

	// Perform the actual scan with the selected provider
	if s.Provider != nil {
		response, err = s.Provider.Scan(purls, &s.Credentials)
		if err != nil {
			return nil, err
		}
	}

	// Load ignore data if specified
	ignoredCVE, err := loader.LoadIgnore(s.IgnoreFile)
	if err != nil {
		util.PrintWarningf("Ignore flag set, but there was an error: %s", err)
	}

	for k, p := range response {
		if len(p.Vulnerabilities) == 0 {
			_ = slices.Delete(response, k, k)
		}
	}

	// Filter, enrich, and ignore vulnerabilities as needed
	s.filterVulnerabilities(response)
	s.ignoreVulnerabilities(response, ignoredCVE)
	s.enrichVulnerabilities(response)

	if s.Output != "json" {
		spinner.Stop()
	}

	return response, nil
}

// detectEcosystems detects the ecosystems from package URLs.
func (s *Scanner) detectEcosystems(purls []string) []string {
	ecosystems := []string{}
	for _, p := range purls {
		purl, err := packageurl.FromString(p)
		if err == nil && !slices.Contains(ecosystems, purl.Type) {
			ecosystems = append(ecosystems, purl.Type)
		}
	}
	return ecosystems
}

// printHeader prints initial information about the scan.
func (s *Scanner) printHeader(purlCount int, ecosystems []string, issues []models.Issue, spinner *spinner.Spinner) {
	if s.Output != "json" {
		util.PrintInfo("Ecosystems detected:", strings.Join(ecosystems, ","))

		supportedEcosystems := s.Provider.SupportedEcosystems()
		if len(supportedEcosystems) > 0 {
			util.PrintInfo("Provider supported ecosystems: ", strings.Join(supportedEcosystems, ","))
		}

		//if any ecosystems in the ecosytems slice are not supported by the provider, print a warning
		for _, e := range ecosystems {
			if !slices.Contains(supportedEcosystems, e) {
				util.PrintWarningf("Provider does not support detected ecosystem: %s\n", e)
			}
		}

		for _, issue := range issues {
			util.PrintWarningf("%v (%v)\n", issue.Message, issue.Purl)
		}

		util.PrintInfof("Scanning %v packages for vulnerabilities...\n", purlCount)
		util.PrintInfo("Vulnerability Provider:", s.getProviderInfo(), "\n")

		spinner.Suffix = fmt.Sprintf(" Fetching vulnerability data from %s", s.ProviderName)
		spinner.Start()
	}
}

func (s *Scanner) getProviderInfo() string {
	if s.Provider == nil {
		return "N/A" // or any other default value or message
	}
	return s.Provider.Info()
}

// filterVulnerabilities filters vulnerabilities based on severity.
func (s *Scanner) filterVulnerabilities(response []models.Package) {
	if s.Severity != "" {
		for i, p := range response {
			vulns := []models.Vulnerability{}
			for _, v := range p.Vulnerabilities {
				fs := ParseSeverity(s.Severity)
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
}

func (s *Scanner) ignoreVulnerabilities(response []models.Package, ignoredCVE []string) {
	for i, p := range response {
		if len(ignoredCVE) > 0 {
			filteredVulnerabilities := filters.Ignore(p.Vulnerabilities, ignoredCVE)
			response[i].Vulnerabilities = filteredVulnerabilities
		}
	}
}

// enrichAndIgnoreVulnerabilities enriches and ignores vulnerabilities as needed.
func (s *Scanner) enrichVulnerabilities(response []models.Package) {
	epssEnricher, _ := enrichers.NewEnricher("epss")
	openaiEnricher, _ := enrichers.NewEnricher("openai")
	for i := range response {
		if slices.Contains(s.Enrichment, "epss") {
			response[i].Vulnerabilities, _ = epssEnricher.Enrich(response[i].Vulnerabilities, &s.Credentials)
		}
	}
	for i := range response {
		if slices.Contains(s.Enrichment, "openai") {
			response[i].Vulnerabilities, _ = openaiEnricher.Enrich(response[i].Vulnerabilities, &s.Credentials)
		}
	}
}

// processResults handles the final processing and output of scan results.
func (s *Scanner) processResults(scanned []models.ScannedFile, licenses []string, response []models.Package) int {
	log.Println("Building severity summary")
	for _, r := range response {
		for _, v := range r.Vulnerabilities {
			AdjustSummary(v.Severity, &s.SeveritySummary)
		}
	}
	log.Println("Creating results")
	// Create results object
	results := models.NewResults(response, s.SeveritySummary, scanned, licenses, s.Version, s.ProviderName, s.Severity)

	// Render results using the specified renderer(s)
	for _, r := range s.Renderers {
		if err := r.Render(results); err != nil {
			log.Println(err)
		}
	}

	// Exit with code if required
	return s.exitWithCodeIfRequired(results)
}

// exitWithCodeIfRequired exits the program with the appropriate code based on severity.
func (s *Scanner) exitWithCodeIfRequired(results models.Results) int {
	if s.ExitCode {
		code := highestSeverityExitCode(FlattenVulnerabilities(results.Packages))
		log.Printf("fail severity: %d", code)
		return code
	}
	return 0
}

// HighestSeverityExitCode returns the exit code of the highest vulnerability
func highestSeverityExitCode(vulnerabilities []models.Vulnerability) int {
	severityExitCodes := map[string]int{
		"UNDEFINED": int(models.UNDEFINED),
		"LOW":       int(models.LOW),
		"MODERATE":  int(models.MODERATE),
		"HIGH":      int(models.HIGH),
		"CRITICAL":  int(models.CRITICAL),
	}

	highestSeverity := "UNDEFINED" // Initialize with the lowest severity
	for _, vulnerability := range vulnerabilities {
		if exitCode, ok := severityExitCodes[vulnerability.Severity]; ok {
			if exitCode > severityExitCodes[highestSeverity] {
				highestSeverity = vulnerability.Severity
			}
		}
	}

	return severityExitCodes[highestSeverity]
}
