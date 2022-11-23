package spdx

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPurls(t *testing.T) {
	var sbom BOM
	err := json.Unmarshal(TestBytes(), &sbom)
	assert.NoError(t, err)
	assert.NotNil(t, sbom)

	purls := sbom.Purls()
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])
}

func TestLicenses(t *testing.T) {
	var sbom BOM
	licenses := sbom.Licenses()

	assert.Len(t, licenses, 0)
}
