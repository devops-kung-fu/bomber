package lib

import (
	"fmt"
	"path/filepath"
	"reflect"
	"strings"
	"time"

	"github.com/gomarkdown/markdown"
	"github.com/microcosm-cc/bluemonday"

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

// FlattenVulnerabilities flattens all vulnerabilities for a package
func FlattenVulnerabilities(packages []models.Package) []models.Vulnerability {
	var flattenedVulnerabilities []models.Vulnerability

	for _, pkg := range packages {
		flattenedVulnerabilities = append(flattenedVulnerabilities, pkg.Vulnerabilities...)
	}

	return flattenedVulnerabilities
}

// UniqueFieldValues returns a slice of unique field values from a slice of structs given a field name
func UniqueFieldValues[T any](input []T, fieldName string) []interface{} {
	// Use a map to store unique field values
	fieldValuesMap := make(map[interface{}]struct{})

	// Iterate through the input slice
	for _, item := range input {
		// Use reflection to get the struct's value
		value := reflect.ValueOf(item)

		// Check if the struct has the specified field
		if fieldValue := value.FieldByName(fieldName); fieldValue.IsValid() {
			// If the field exists, add its value to the map
			fieldValuesMap[fieldValue.Interface()] = struct{}{}
		}
		// If the field doesn't exist, do nothing

	}

	// Create a slice to store unique field values
	var uniqueFieldValuesSlice []interface{}

	// Iterate through the map keys and add them to the slice
	for fieldValue := range fieldValuesMap {
		uniqueFieldValuesSlice = append(uniqueFieldValuesSlice, fieldValue)
	}

	return uniqueFieldValuesSlice
}

// markdownToHTML converts the Markdown descriptions of vulnerabilities in
// the given results to HTML. It uses the Blackfriday library to perform the
// conversion and sanitizes the HTML using Bluemonday.
func MarkdownToHTML(results models.Results) {
	for i := range results.Packages {
		for ii := range results.Packages[i].Vulnerabilities {
			md := []byte(results.Packages[i].Vulnerabilities[ii].Description)
			html := markdown.ToHTML(md, nil, nil)
			results.Packages[i].Vulnerabilities[ii].Description = string(bluemonday.UGCPolicy().SanitizeBytes(html))
		}
	}
}

// generateFilename generates a unique filename based on the current timestamp
// in the format "2006-01-02 15:04:05" and replaces certain characters to
// create a valid filename. The resulting filename is a combination of the
// timestamp and a fixed suffix.
// TODO: Need to make this generic. It's only being used for HTML Renderers
func GenerateFilename() string {
	t := time.Now()
	r := strings.NewReplacer("-", "", " ", "-", ":", "-")
	return filepath.Join(".", fmt.Sprintf("%s-bomber-results.html", r.Replace(t.Format("2006-01-02 15:04:05"))))
}
