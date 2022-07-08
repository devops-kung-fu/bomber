package cyclonedx

import (
	"testing"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/stretchr/testify/assert"
)

func TestToSPDX(t *testing.T) {
	c := cyclone.NewBOM()
	bom := ToSPDX(c)
	assert.NotNil(t, bom)
}
