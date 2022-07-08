package structs

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSPDX(t *testing.T) {
	bom := NewSPDX()
	assert.IsType(t, SPDX{}, bom)
	assert.NotNil(t, bom)
}
