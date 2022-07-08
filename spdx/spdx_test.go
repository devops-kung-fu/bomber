package spdx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSPDX(t *testing.T) {
	bom := NewSPDX()
	assert.NotNil(t, bom)
}

func TestToCycloneDX(t *testing.T) {
	bom := ToCycloneDX(NewSPDX())
	assert.NotNil(t, bom)
}
