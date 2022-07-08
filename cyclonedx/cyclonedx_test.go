package cyclonedx

import (
	"testing"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestNewSBOM(t *testing.T) {
	bom := NewBOM()
	assert.NotNil(t, bom)
}

func TestToSPDX(t *testing.T) {
	c := cyclone.NewBOM()
	bom := ToSPDX(c)
	assert.NotNil(t, bom)
}
