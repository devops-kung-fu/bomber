package enrichers

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/enrichers/epss"
)

func TestNewEnricher(t *testing.T) {
	enricher, err := NewEnricher("epss")
	assert.NoError(t, err)
	assert.IsType(t, epss.Enricher{}, enricher)
	_, err = NewEnricher("test")
	assert.Error(t, err)
}
