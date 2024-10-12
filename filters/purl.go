package filters

import (
	"strings"

	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

// Sanitize removes any invalid package URLs from the slice
func Sanitize(purls []string) (sanitized []string, issues []models.Issue) {
	for _, p := range purls {
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

// func sanitizePurl(input string) string {
// 	re := regexp.MustCompile(`[^a-zA-Z0-9@/\.:-?=]+`)
// 	sanitized := re.ReplaceAllString(input, "")

// 	// Check if the sanitized string ends with a semantic version
// 	semverPattern := `@\d+\.\d+\.\d+`
// 	semverRegex := regexp.MustCompile(semverPattern)
// 	if semverRegex.MatchString(sanitized) {
// 		// Extract the semantic version
// 		version := semverRegex.FindString(sanitized)
// 		// Remove invalid characters before the version
// 		sanitized = re.ReplaceAllString(strings.Split(sanitized, version)[0], "") + version
// 	} else {
// 		// Remove the at symbol and anything that follows it if no valid version is found
// 		sanitized = strings.Split(sanitized, "@")[0]
// 	}

// 	return sanitized
// }
