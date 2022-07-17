package spdx

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestNewSPDX(t *testing.T) {
	bom := NewBOM()
	assert.NotNil(t, bom)
}

func TestToCycloneDX(t *testing.T) {
	bom := ToCycloneDX(NewBOM())
	assert.NotNil(t, bom)
}
