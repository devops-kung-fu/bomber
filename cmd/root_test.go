// Package cmd contains all of the commands that may be executed in the cli
package cmd

import (
	"testing"

	"github.com/devops-kung-fu/common/util"
	"github.com/stretchr/testify/assert"
)

func Test_printAsciiArt(t *testing.T) {
	output := util.CaptureOutput(func() {
		printAsciiArt()
	})
	assert.NotNil(t, output)
	assert.Len(t, output, 0)
}
