// Package lib contains core functionality to load Software Bill of Materials and contains common functions
package lib

import (
	"testing"

	"github.com/devops-kung-fu/common/util"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	"github.com/devops-kung-fu/bomber/models"
)

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

func Test_loadIgnoreData(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/.bomber.ignore", []byte("CVE-2022-31163"), 0644)
	assert.NoError(t, err)

	scanner := Scanner{}
	results, err := scanner.loadIgnoreData(afs, "/.bomber.ignore")

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, results[0], "CVE-2022-31163")

	_, err = scanner.loadIgnoreData(afs, "test")
	assert.Error(t, err)

	results, err = scanner.loadIgnoreData(afs, "")
	assert.NoError(t, err)
	assert.Len(t, results, 0)
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

		code, err := scanner.Scan([]string{"/test-cyclonedx.json"})
		assert.NoError(t, err)
		assert.Equal(t, 0, code)

		scanner.Output = "stdout"
		code, err = scanner.Scan([]string{"/test-cyclonedx.json"})
		assert.NoError(t, err)
		assert.Equal(t, 0, code)
	})

	assert.NotNil(t, output)
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

func Test_FilterVulngerabilities(t *testing.T) {
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
