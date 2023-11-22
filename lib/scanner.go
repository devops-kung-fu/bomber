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

	"github.com/devops-kung-fu/bomber/lib/enrichment"
	"github.com/devops-kung-fu/bomber/lib/filters"
	"github.com/devops-kung-fu/bomber/models"
)

// Scanner represents a vulnerability scanner.
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
	Afs             *afero.Afero
}

var loader Loader

// Scan performs the vulnerability scan.
func (s *Scanner) Scan(args []string) (exitCode int, err error) {
	loader := Loader{
		s.Afs,
	}
	// Load packages and associated data
	scanned, purls, licenses, err := loader.Load(args)
	if err != nil {
		log.Print(err)
		return
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
	spinner := spinner.New(spinner.CharSets[9], 100*time.Millisecond)

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
	ignoredCVE, err := s.loadIgnoreData(s.IgnoreFile)
	if err != nil {
		util.PrintWarningf("Ignore flag set, but there was an error: %s", err)
	}

	// Filter, enrich, and ignore vulnerabilities as needed
	s.filterVulnerabilities(response)
	s.enrichAndIgnoreVulnerabilities(response, ignoredCVE)

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

// loadIgnoreData loads the ignore data from a file if specified.
func (s *Scanner) loadIgnoreData(ignoreFile string) ([]string, error) {
	if ignoreFile != "" {
		return loader.LoadIgnore(ignoreFile)
	}
	return nil, nil
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

// enrichAndIgnoreVulnerabilities enriches and ignores vulnerabilities as needed.
func (s *Scanner) enrichAndIgnoreVulnerabilities(response []models.Package, ignoredCVE []string) {
	for i, p := range response {
		enrichedVulnerabilities, _ := enrichment.Enrich(p.Vulnerabilities)
		response[i].Vulnerabilities = enrichedVulnerabilities

		if len(ignoredCVE) > 0 {
			filteredVulnerabilities := filters.Ignore(p.Vulnerabilities, ignoredCVE)
			response[i].Vulnerabilities = filteredVulnerabilities
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

	// Render results using the specified renderer
	if s.Renderer != nil {
		if err := s.Renderer.Render(results); err != nil {
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
