package renderers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/renderers/ai"
	"github.com/devops-kung-fu/bomber/renderers/html"
	"github.com/devops-kung-fu/bomber/renderers/json"
	"github.com/devops-kung-fu/bomber/renderers/jsonfile"
	"github.com/devops-kung-fu/bomber/renderers/md"
	"github.com/devops-kung-fu/bomber/renderers/stdout"
)

func TestNewRenderer(t *testing.T) {
	renderers, err := NewRenderer("stdout")
	assert.NoError(t, err)
	assert.IsType(t, stdout.Renderer{}, renderers[0])

	renderers, err = NewRenderer("json")
	assert.NoError(t, err)
	assert.IsType(t, json.Renderer{}, renderers[0])

	renderers, err = NewRenderer("html")
	assert.NoError(t, err)
	assert.IsType(t, html.Renderer{}, renderers[0])

	renderers, err = NewRenderer("ai")
	assert.NoError(t, err)
	assert.IsType(t, ai.Renderer{}, renderers[0])

	renderers, err = NewRenderer("json-file")
	assert.NoError(t, err)
	assert.IsType(t, jsonfile.Renderer{}, renderers[0])

	renderers, err = NewRenderer("stdout,json-file,html,json")
	assert.NoError(t, err)
	assert.IsType(t, stdout.Renderer{}, renderers[0])
	assert.IsType(t, jsonfile.Renderer{}, renderers[1])
	assert.IsType(t, html.Renderer{}, renderers[2])
	assert.IsType(t, json.Renderer{}, renderers[3])
	assert.Len(t, renderers, 4)

	renderers, err = NewRenderer("md")
	assert.NoError(t, err)
	assert.IsType(t, md.Renderer{}, renderers[0])

	_, err = NewRenderer("test")
	assert.Error(t, err)
}
