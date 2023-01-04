package cyclonedx

import (
	"encoding/json"
	"testing"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestPurls(t *testing.T) {
	var sbom cyclone.BOM
	err := json.Unmarshal(TestBytes(), &sbom)
	assert.NoError(t, err)
	assert.NotNil(t, sbom)

	purls := Purls(&sbom)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])
}

func TestLicenses(t *testing.T) {
	var sbom cyclone.BOM
	err := json.Unmarshal(TestBytes(), &sbom)
	assert.NoError(t, err)
	assert.NotNil(t, sbom)

	licenses := Licenses(&sbom)

	assert.Len(t, licenses, 2)
}
