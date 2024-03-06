package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestSanitize(t *testing.T) {
	// Input test data
	purls := []string{
		"pkg:github.com/user/repo",
		"file:/path/to/file",
		"pkg:github.com/user/repo/file",
		"file:/path/to/another/file",
	}

	// Expected output
	expectedSanitized := []string{
		"pkg:github.com/user/repo",
		"pkg:github.com/user/repo/file",
	}
	expectedIssues := []models.Issue{
		{
			IssueType: "InvalidPackageURL",
			Message:   "Ignoring an invalid package URL",
			Purl:      "file:/path/to/file",
		},
		{
			IssueType: "InvalidPackageURL",
			Message:   "Ignoring an invalid package URL",
			Purl:      "file:/path/to/another/file",
		},
	}

	// Call the function
	sanitized, issues := Sanitize(purls)

	// Assert the results
	assert.ElementsMatch(t, expectedSanitized, sanitized)
	assert.ElementsMatch(t, expectedIssues, issues)
}
