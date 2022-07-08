package structs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewCycloneDX(t *testing.T) {
	bom := NewCycloneDX()
	assert.IsType(t, Cyclonedx{}, bom)
	assert.NotNil(t, bom)
}
