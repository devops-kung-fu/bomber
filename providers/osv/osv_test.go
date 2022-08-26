package osv

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	info := Info()
	assert.Equal(t, "UNDER DEVELOPMENT: OSV Vulnerability Database (https://osv.dev)", info)
}
