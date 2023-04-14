package filters

import (
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

// Sanitize removes any invalid package URLs from the slice
func Sanitize(purls []string) (sanitized []string, issues []models.Issue) {
	for _, p := range purls {
		if !strings.Contains(p, "file:") {
			if _, err := packageurl.FromString(p); err == nil {
				sanitized = append(sanitized, p)
			}
		} else {
			//append a new models.Issue to the issues slice
			issues = append(issues, models.Issue{
				IssueType: "InvalidPackageURL",
				Message:   "Ignoring an invalid package URL",
				Purl:      p,
			})
		}
	}
	return
}
