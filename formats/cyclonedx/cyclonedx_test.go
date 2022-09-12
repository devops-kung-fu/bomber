package cyclonedx

import (
	"encoding/json"
	"testing"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestPurls(t *testing.T) {
	var sbom cyclone.BOM
	err := json.Unmarshal(CycloneDXTestBytes(), &sbom)
	assert.NoError(t, err)
	assert.NotNil(t, sbom)

	purls := Purls(&sbom)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])
}
