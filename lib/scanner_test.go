package lib

import (
	"testing"

	"github.com/devops-kung-fu/common/util"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	"github.com/devops-kung-fu/bomber/models"
)

// MockProvider is a mock implementation of the Provider interface for testing purposes
type MockProvider struct{}

func (mp MockProvider) Scan(purls []string, credentials *models.Credentials) (packages []models.Package, err error) {
	return []models.Package{}, nil
}

// Info returns a mock provider info string
func (mp MockProvider) Info() string {
	return "MockProviderInfo"
}

func Test_detectEcosystems(t *testing.T) {
	scanner := Scanner{}

	purls := []string{
		"pkg:golang/github.com/test/test1@v1.19.0",
		"pkg:npm/github.com/test/test2@v1.19.0",
		"invalid_url", // This should be ignored
	}

	result := scanner.detectEcosystems(purls)

	assert.ElementsMatch(t, []string{"golang", "npm"}, result, "Detected ecosystems do not match expected result")
}

func TestScanner_Scan(t *testing.T) {
	output := util.CaptureOutput(func() {
		afs := &afero.Afero{Fs: afero.NewMemMapFs()}

		err := afs.WriteFile("/test-cyclonedx.json", cyclonedx.TestBytes(), 0644)
		assert.NoError(t, err)

		scanner := Scanner{
			Output: "json",
			Afs:    afs,
		}

		code, err := scanner.Scan([]string{})
		assert.NoError(t, err)
		assert.Equal(t, 0, code)

		code, err = scanner.Scan([]string{"/test-cyclonedx.json"})
		assert.NoError(t, err)
		assert.Equal(t, 0, code)

		scanner.Output = "stdout"
		code, err = scanner.Scan([]string{"/test-cyclonedx.json"})
		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	assert.NotNil(t, output)
}

func TestScanner_Scan_BadFileName(t *testing.T) {
	scanner := Scanner{
		ExitCode: false,
		Afs:      &afero.Afero{Fs: afero.NewMemMapFs()},
	}
	_, err := scanner.Scan([]string{"test**.json"})
	assert.Error(t, err)
}

func TestScanner_exitWithCodeIfRequired(t *testing.T) {
	scanner := Scanner{
		ExitCode: false,
	}
	code := scanner.exitWithCodeIfRequired(models.Results{})
	assert.Equal(t, 0, code)

	scanner.ExitCode = true
	code = scanner.exitWithCodeIfRequired(models.Results{})
	assert.Equal(t, 10, code)
}

func TestScanner_enrichVulnerabilities(t *testing.T) {
	// Create a sample Scanner instance
	scanner := Scanner{}
	scanner.Enrichment = []string{"epss"}

	// Create a sample response with vulnerabilities
	response := []models.Package{
		{
			Purl: "sample/package",
			Vulnerabilities: []models.Vulnerability{
				{ID: "1", Title: "Vuln1", Cve: "CVE-2024-3094"},
				{ID: "2", Title: "Vuln2", Cve: "CVE-2024-3094"},
			},
		},
	}
	
	scanner.enrichVulnerabilities(response)

	assert.Len(t, response[0].Vulnerabilities, 2)
	assert.NotNil(t, response[0].Vulnerabilities[1].Epss)
	assert.NotEmpty(t, response[0].Vulnerabilities[1].Explanation)
	assert.NotEmpty(t, response[0].Vulnerabilities[1].Explanation)

	// t.Run("IgnoreVulnerabilities", func(t *testing.T) {
	// 	// Create a sample Scanner instance
	// 	scanner := Scanner{}

	// 	// Create a sample response with vulnerabilities
	// 	response := []models.Package{
	// 		{
	// 			Purl: "sample/package",
	// 			Vulnerabilities: []models.Vulnerability{
	// 				{ID: "1", Title: "Vuln1"},
	// 				{ID: "2", Title: "Vuln2"},
	// 			},
	// 		},
	// 	}

	// 	// Call the enrichAndIgnoreVulnerabilities method with ignoredCVE
	// 	scanner.ignoreVulnerabilities(response, []string{"1"})

	// 	// Check if the specified vulnerabilities have been ignored
	// 	assert.Len(t, response[0].Vulnerabilities, 1)
	// 	assert.Equal(t, "Vuln2", response[0].Vulnerabilities[0].Title)
	// })
}

func TestScanner_ignoreVulnerabilities(t *testing.T) {
	// Create a sample Scanner instance
	scanner := Scanner{}

	// Create a sample response with vulnerabilities
	response := []models.Package{
		{
			Purl: "sample/package",
			Vulnerabilities: []models.Vulnerability{
				{ID: "1", Title: "Vuln1"},
				{ID: "2", Title: "Vuln2"},
			},
		},
	}

	// Call the enrichAndIgnoreVulnerabilities method with ignoredCVE
	scanner.ignoreVulnerabilities(response, []string{"1"})

	// Check if the specified vulnerabilities have been ignored
	assert.Len(t, response[0].Vulnerabilities, 1)
	assert.Equal(t, "Vuln2", response[0].Vulnerabilities[0].Title)

}

func TestFilterVulnerabilities(t *testing.T) {
	// Create a sample Scanner instance with a severity filter
	scanner := Scanner{Severity: "HIGH"}

	// Create a sample response with vulnerabilities
	response := []models.Package{
		{
			Purl: "sample/package",
			Vulnerabilities: []models.Vulnerability{
				{Severity: "LOW"},
				{Severity: "MODERATE"},
				{Severity: "HIGH"},
				{Severity: "CRITICAL"},
			},
		},
		{
			Purl: "another/package",
			Vulnerabilities: []models.Vulnerability{
				{Severity: "LOW"},
				{Severity: "HIGH"},
				{Severity: "CRITICAL"},
			},
		},
	}

	// Call the filterVulnerabilities method
	scanner.filterVulnerabilities(response)

	// Check if the vulnerabilities have been filtered correctly
	assert.Equal(t, "HIGH", response[0].Vulnerabilities[0].Severity)
	assert.Equal(t, 2, len(response[0].Vulnerabilities)) // Expecting other severities to be filtered out

	assert.Equal(t, "HIGH", response[1].Vulnerabilities[0].Severity)
	assert.Equal(t, "CRITICAL", response[1].Vulnerabilities[1].Severity)
	assert.Equal(t, 0, len(response[1].Vulnerabilities)-2) // Expecting LOW severity to be filtered out
}

func TestScannerGetProviderInfo(t *testing.T) {
	t.Run("WithMockProvider", func(t *testing.T) {
		scanner := Scanner{Provider: MockProvider{}}
		result := scanner.getProviderInfo()

		assert.Equal(t, "MockProviderInfo", result)
	})

	t.Run("WithNilProvider", func(t *testing.T) {
		scanner := Scanner{Provider: nil}
		result := scanner.getProviderInfo()

		assert.Equal(t, "N/A", result)
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
	actualExitCode := highestSeverityExitCode(vulnerabilities)
	assert.Equal(t, expectedExitCode, actualExitCode)
}
