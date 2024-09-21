package providers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/providers/ossindex"
	"github.com/devops-kung-fu/bomber/providers/osv"
	"github.com/devops-kung-fu/bomber/providers/snyk"
	"github.com/devops-kung-fu/bomber/providers/gad"
)

func TestNewProvider(t *testing.T) {
	provider, err := NewProvider("ossindex")
	assert.NoError(t, err)
	assert.IsType(t, ossindex.Provider{}, provider)

	provider, err = NewProvider("osv")
	assert.NoError(t, err)
	assert.IsType(t, osv.Provider{}, provider)

	provider, err = NewProvider("snyk")
	assert.NoError(t, err)
	assert.IsType(t, snyk.Provider{}, provider)

	provider, err = NewProvider("gad")
	assert.NoError(t, err)
	assert.IsType(t, gad.Provider{}, provider)

	_, err = NewProvider("test")
	assert.Error(t, err)
}
