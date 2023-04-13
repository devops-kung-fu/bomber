package filters

import (
	"strings"

	"github.com/package-url/packageurl-go"
)

func Sanitize(purls []string) (sanitized []string) {
	for i, p := range purls {
		add := true
		if strings.Contains(p, "file:") {
			add = false
		}

		if _, err := packageurl.FromString(p); err != nil {
			add = false
		}

		if add {
			sanitized = append(sanitized, purls[i])
		}
	}
	return
}
