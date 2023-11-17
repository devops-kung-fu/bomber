package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func Test_Rating(t *testing.T) {
	rating := 0.0
	result := Rating(rating)
	assert.Equal(t, "UNSPECIFIED", result)

	rating = 1.0
	result = Rating(rating)
	assert.Equal(t, "LOW", result)

	rating = 4.0
	result = Rating(rating)
	assert.Equal(t, "MODERATE", result)

	rating = 7.0
	result = Rating(rating)
	assert.Equal(t, "HIGH", result)

	rating = 9.0
	result = Rating(rating)
	assert.Equal(t, "CRITICAL", result)

	rating = 19.0
	result = Rating(rating)
	assert.Equal(t, "UNSPECIFIED", result)
}

func TestAdjustSummary(t *testing.T) {
	summary := models.Summary{}

	AdjustSummary("CRITICAL", &summary)
	AdjustSummary("HIGH", &summary)
	AdjustSummary("MODERATE", &summary)
	AdjustSummary("LOW", &summary)
	AdjustSummary("UNSPECIFIED", &summary)

	assert.Equal(t, summary.Critical, 1)
	assert.Equal(t, summary.High, 1)
	assert.Equal(t, summary.Moderate, 1)
	assert.Equal(t, summary.Low, 1)
	assert.Equal(t, summary.Unspecified, 1)

	AdjustSummary("UNSPECIFIED", &summary)
	assert.Equal(t, summary.Unspecified, 2)
}

func TestParseSeverity(t *testing.T) {
	t.Run("Valid severity: low", func(t *testing.T) {
		severity := "low"
		expected := 11
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: moderate", func(t *testing.T) {
		severity := "moderate"
		expected := 12
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: high", func(t *testing.T) {
		severity := "high"
		expected := 13
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: critical", func(t *testing.T) {
		severity := "critical"
		expected := 14
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Invalid severity: invalid", func(t *testing.T) {
		severity := "invalid"
		expected := 0
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Mixed case severity: moderate", func(t *testing.T) {
		severity := "MoDerAte"
		expected := 12
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: undefined", func(t *testing.T) {
		severity := "undefined"
		expected := 10
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})
}

func TestHighestSeverityExitCode(t *testing.T) {
	// Sample vulnerabilities with different severities
	vulnerabilities := []models.Vulnerability{
		{Severity: "LOW"},
		{Severity: "CRITICAL"},
		{Severity: "MODERATE"},
		{Severity: "HIGH"},
		{Severity: "UNDEFINED"},
	}

	// Calculate the expected exit code based on the highest severity
	expectedExitCode := 14 // CRITICAL has the highest severity

	// Call the function and check the result using assert
	actualExitCode := HighestSeverityExitCode(vulnerabilities)
	assert.Equal(t, expectedExitCode, actualExitCode)
}

func TestFlattenVulnerabilities(t *testing.T) {
	// Create some sample data for testing
	pkg1 := models.Package{
		Purl: "pkg1",
		Vulnerabilities: []models.Vulnerability{
			{DisplayName: "Vuln1", Severity: "LOW"},
			{DisplayName: "Vuln2", Severity: "HIGH"},
		},
	}

	pkg2 := models.Package{
		Purl: "pkg2",
		Vulnerabilities: []models.Vulnerability{
			{DisplayName: "Vuln3", Severity: "MODERATE"},
		},
	}

	// Slice of Packages to test
	packages := []models.Package{pkg1, pkg2}

	// Call the FlattenVulnerabilities function
	flattenedVulnerabilities := FlattenVulnerabilities(packages)

	// Define the expected result
	expectedVulnerabilities := []models.Vulnerability{
		{DisplayName: "Vuln1", Severity: "LOW"},
		{DisplayName: "Vuln2", Severity: "HIGH"},
		{DisplayName: "Vuln3", Severity: "MODERATE"},
	}

	// Check if the actual result matches the expected result using assert.ElementsMatch
	assert.ElementsMatch(t, expectedVulnerabilities, flattenedVulnerabilities)
}

func Test_UniqueFieldValues(t *testing.T) {
	type TestStruct struct {
		CVE string
		// other properties...
	}
	structs := []TestStruct{
		{CVE: "CVE-2021-1234"},
		{CVE: "CVE-2021-5678"},
		{CVE: "CVE-2021-1234"}, // Duplicate
	}

	// Get unique CVEs using the function
	uniqueCVEs := UniqueFieldValues(structs, "CVE")
	assert.Len(t, uniqueCVEs, 2)

	shouldBeNothing := UniqueFieldValues(structs, "ABC")
	assert.Len(t, shouldBeNothing, 0)
}
