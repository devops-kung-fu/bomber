package lib

import (
	"strings"

	"github.com/devops-kung-fu/bomber/models"
)

// Rating takes a CVSS score as input and returns a rating string based on the score
func Rating(score float64) string {
	switch {
	case score == 0.0:
		return "UNSPECIFIED"
	case score <= 3.9:
		return "LOW"
	case score <= 6.9:
		return "MODERATE"
	case score <= 8.9:
		return "HIGH"
	case score <= 10.0:
		return "CRITICAL"
	default:
		return "UNSPECIFIED"
	}
}

// AdjustSummary takes a severity string and a pointer to a Summary struct as input, and increments the corresponding severity count in the struct.
func AdjustSummary(severity string, summary *models.Summary) {
	severity = strings.ToUpper(severity)

	switch severity {
	case "LOW":
		summary.Low++
	case "MODERATE":
		summary.Moderate++
	case "HIGH":
		summary.High++
	case "CRITICAL":
		summary.Critical++
	default:
		summary.Unspecified++
	}
}

// ParseSeverity takes a severity string and returns an int
func ParseSeverity(severity string) int {
	severity = strings.ToUpper(severity)
	switch severity {
	case "LOW":
		return int(models.LOW)
	case "MODERATE":
		return int(models.MODERATE)
	case "HIGH":
		return int(models.HIGH)
	case "CRITICAL":
		return int(models.CRITICAL)
	case "UNDEFINED":
		return int(models.UNDEFINED)
	default:
		return 0
	}
}

// HighestSeverityExitCode returns the exit code of the highest vulnerability
func HighestSeverityExitCode(vulnerabilities []models.Vulnerability) int {
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

func FlattenVulnerabilities(packages []models.Package) []models.Vulnerability {
	var flattenedVulnerabilities []models.Vulnerability

	for _, pkg := range packages {
		flattenedVulnerabilities = append(flattenedVulnerabilities, pkg.Vulnerabilities...)
	}

	return flattenedVulnerabilities
}
