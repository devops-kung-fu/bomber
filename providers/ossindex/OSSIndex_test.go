package ossindex

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	info := Info()
	assert.Equal(t, "Sonatype OSS Index (https://ossindex.sonatype.org)", info)
}
