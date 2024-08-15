package filters

import (
	"regexp"
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

// Sanitize removes any invalid package URLs from the slice
func Sanitize(purls []string) (sanitized []string, issues []models.Issue) {
	for _, p := range purls {
		p := sanitizePurl(p)
		purl, err := packageurl.FromString(p)
		if err != nil {
			//append a new models.Issue to the issues slice
			issues = append(issues, models.Issue{
				IssueType: "InvalidPackageURL",
				Message:   "Ignoring an invalid package URL",
				Purl:      p,
			})
			continue
		}
		err = purl.Normalize()
		if err != nil {
			//append a new models.Issue to the issues slice
			issues = append(issues, models.Issue{
				IssueType: "InvalidPackageURL",
				Message:   "Ignoring an invalid package URL",
				Purl:      p,
			})
			continue
		}
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

func sanitizePurl(input string) string {
	re := regexp.MustCompile(`[^a-zA-Z0-9@/\.:-?-=]+`)
	sanitized := re.ReplaceAllString(input, "")

	// Check if the sanitized string ends with a semantic version
	semverPattern := `^.*@\d+\.\d+\.\d+$`
	semverRegex := regexp.MustCompile(semverPattern)
	if !semverRegex.MatchString(sanitized) {
		// Check if the sanitized string ends with a semantic version followed by a question mark
		semverWithQueryPattern := `^.*@\d+\.\d+\.\d+\?.*$`
		semverWithQueryRegex := regexp.MustCompile(semverWithQueryPattern)
		if !semverWithQueryRegex.MatchString(sanitized) {
			// Remove the at symbol and anything that follows it
			sanitized = strings.Split(sanitized, "@")[0]
		}
	}

	return sanitized
}
