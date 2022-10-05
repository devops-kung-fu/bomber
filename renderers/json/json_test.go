package json

import (
	"testing"

	"github.com/devops-kung-fu/common/util"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestRenderer_Render(t *testing.T) {
	output := util.CaptureOutput(func() {
		renderer := Renderer{}
		renderer.Render(models.NewResults([]models.Package{}, models.Summary{}, []string{"GPL"}, "0.0.0", "test"))
	})
	assert.True(t, true)
	assert.NotNil(t, output)
	assert.Contains(t, output, "generator\": \"bomber\"")
}
