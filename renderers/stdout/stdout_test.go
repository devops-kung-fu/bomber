package stdout

import (
	"testing"

	"github.com/devops-kung-fu/common/util"
	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestRenderer_Render(t *testing.T) {
	output := util.CaptureOutput(func() {
		packages := []models.Package{
			{
				Purl: "pkg:golang/github.com/briandowns/spinner@v1.19.0",
				Vulnerabilities: []models.Vulnerability{
					{
						ID:       "Test",
						Severity: "CRITICAL",
					},
				},
			},
		}
		renderer := Renderer{}
		renderer.Render(models.NewResults(packages, models.Summary{}, []models.ScannedFile{}, []string{"GPL"}, "0.0.0", "test"))
	})
	assert.NotNil(t, output)
	assert.Contains(t, output, "golang │ spinner │ v1.19.0 │ CRITICAL")
}

func Test_vulnerabilityCount(t *testing.T) {
	count := vulnerabilityCount([]models.Package{
		{
			Purl: "test",
			Vulnerabilities: []models.Vulnerability{
				{
					ID: "test",
				},
			},
		},
		{
			Purl: "test",
			Vulnerabilities: []models.Vulnerability{
				{
					ID: "test",
				},
				{
					ID: "test",
				},
			},
		},
	})
	assert.Equal(t, 3, count)
}

func Test_renderSeveritySummary(t *testing.T) {
	output := util.CaptureOutput(func() {
		renderSeveritySummary(models.Summary{
			Unspecified: 1,
		})
	})
	assert.NotNil(t, output)
	assert.Contains(t, output, "│ RATING")
}
