package osv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	info := Info()
	assert.Equal(t, "OSV Vulnerability Database (https://osv.dev) - EXPERIMENTAL", info)
}
