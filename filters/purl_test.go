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

func TestSanitizePurl(t *testing.T) {
	testCases := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "ValidSemVer",
			input:    "pkg:maven/\"org.apache.commons/commons-vfs2\"@2.3.1",
			expected: "pkg:maven/org.apache.commons/commons-vfs2@2.3.1",
		},
		{
			name:     "InvalidSemVer",
			input:    "pkg:maven/\"org.apache.commons/commons-vfs2\"@%20{",
			expected: "pkg:maven/org.apache.commons/commons-vfs2",
		},
		{
			name:     "NoSemVer",
			input:    "pkg:maven/\"org.apache.commons/commons-vfs2\"",
			expected: "pkg:maven/org.apache.commons/commons-vfs2",
		},
		{
			name:     "InvalidChars",
			input:    "pkg:maven/\"org.apache.commons/commons-vfs2\"@2.3.1#$%^&*",
			expected: "pkg:maven/org.apache.commons/commons-vfs2@2.3.1",
		},
		{
			name:     "EmptyString",
			input:    "",
			expected: "",
		},
		{
			name:     "SemVerWithQuery",
			input:    "pkg:maven/\"org.apache.commons/commons-vfs2\"@2.3.1?qualifier=abc",
			expected: "pkg:maven/org.apache.commons/commons-vfs2@2.3.1?qualifier=abc",
		},
		{
			name:     "LongPurl",
			input:    "pkg:rpm/opensuse/curl@7.56.1-1.1.?arch=i386&distro=opensuse-tumbleweed",
			expected: "pkg:rpm/opensuse/curl",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			actual := sanitizePurl(tc.input)
			assert.Equal(t, tc.expected, actual)
		})
	}
}
