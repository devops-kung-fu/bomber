package lib

import (
	"strings"

	"github.com/devops-kung-fu/bomber/models"
)

// Rating takes a CVSS score as input and returns a rating string based on the score
func Rating(score float64) string {
	switch {
	case score > 0 && score <= 3.9:
		return "LOW"
	case score >= 4.0 && score <= 6.9:
		return "MODERATE"
	case score >= 7.0 && score <= 8.9:
		return "HIGH"
	case score >= 9.0 && score <= 10.0:
		return "CRITICAL"
	default:
		return "UNSPECIFIED"
	}
}

// AdjustSummary takes a severity string and a pointer to a Summary struct as input, and increments the corresponding severity count in the struct.
func AdjustSummary(severity string, summary *models.Summary) {
	switch strings.ToUpper(severity) {
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
