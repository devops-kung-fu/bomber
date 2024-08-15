package html

import (
	"fmt"
	"os"
	"testing"

	"github.com/devops-kung-fu/common/util"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func Test_writeTemplate(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := writeTemplate(afs, "test.html", models.NewResults([]models.Package{}, models.Summary{}, []models.ScannedFile{}, []string{"GPL"}, "0.0.0", "test", "low"))
	assert.NoError(t, err)

	b, err := afs.ReadFile("test.html")
	assert.NotNil(t, b)
	assert.NoError(t, err)

	info, err := afs.Stat("test.html")
	assert.NoError(t, err)
	assert.Equal(t, os.FileMode(0644), info.Mode().Perm())
}

func Test_genTemplate(t *testing.T) {
	template := genTemplate("test")

	assert.NotNil(t, template)
	assert.Len(t, template.Tree.Root.Nodes, 17)
}

func TestRenderer_Render(t *testing.T) {
	output := util.CaptureOutput(func() {
		renderer := Renderer{}
		err := renderer.Render(models.NewResults([]models.Package{}, models.Summary{}, []models.ScannedFile{}, []string{"GPL"}, "0.0.0", "test", ""))
		if err != nil {
			fmt.Println(err)
		}
	})
	assert.NotNil(t, output)
}

func Test_processPercentiles(t *testing.T) {
	// Create a sample Results struct for testing
	results := models.Results{
		Packages: []models.Package{
			{
				Vulnerabilities: []models.Vulnerability{
					{
						Epss: models.EpssScore{Percentile: "0.75"},
					},
					{
						Epss: models.EpssScore{Percentile: "invalid"}, // Simulate an invalid percentile
					},
					{
						Epss: models.EpssScore{Percentile: "0"}, // Simulate a zero percentile
					},
				},
			},
		},
	}

	processPercentiles(results)

	assert.Equal(t, "75%", results.Packages[0].Vulnerabilities[0].Epss.Percentile, "Expected 75% percentile")
	assert.Equal(t, "invalid", results.Packages[0].Vulnerabilities[1].Epss.Percentile, "Expected invalid for invalid percentile")
	assert.Equal(t, "N/A", results.Packages[0].Vulnerabilities[2].Epss.Percentile, "Expected N/A for zero percentile")
}

