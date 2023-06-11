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

// ParseFailSeverity takes a string and returns a FailSeverity enum
func ParseFailSeverity(s string) models.FailSeverity {
	s = strings.ToLower(s)

	switch s {
	case "low":
		return models.LOW
	case "moderate":
		return models.MODERATE
	case "high":
		return models.HIGH
	case "critical":
		return models.CRITICAL
	default:
		return models.UNDEFINED
	}
}
