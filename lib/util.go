package lib

import (
	"strings"

	"github.com/devops-kung-fu/bomber/models"
)

func Rating(score float64) string {
	if score > 0 && score <= 3.9 {
		return "LOW"
	} else if score >= 4.0 && score <= 6.9 {
		return "MODERATE"
	} else if score >= 7.0 && score <= 8.9 {
		return "HIGH"
	} else if score >= 9.0 && score <= 10.0 {
		return "CRITICAL"
	}
	return "UNSPECIFIED"
}

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
