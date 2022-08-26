package snyk

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	info := Info()
	assert.Equal(t, "Snyk (https://snyk.com)", info)
}
