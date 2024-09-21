package gad

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	provider := Provider{}
	info := provider.Info()
	assert.Equal(t, "GitHub Advisory Database (https://github.com/advisories)", info)
}
