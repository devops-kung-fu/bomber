package html

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func Test_writeTemplate(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := writeTemplate(afs, "test.html", models.NewResults([]models.Package{}, models.Summary{}, []string{"GPL"}, "0.0.0", "test"))
	assert.NoError(t, err)

	b, err := afs.ReadFile("test.html")
	assert.NotNil(t, b)
	assert.NoError(t, err)
}

func Test_genTemplate(t *testing.T) {
	template := genTemplate("test")

	assert.NotNil(t, template)
	assert.Len(t, template.Tree.Root.Nodes, 15)
}
