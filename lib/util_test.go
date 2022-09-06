package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestRating(t *testing.T) {
	rating := 0.0
	result := Rating(rating)
	assert.Equal(t, "UNSPECIFIED", result)

	rating = 1.0
	result = Rating(rating)
	assert.Equal(t, "LOW", result)

	rating = 4.0
	result = Rating(rating)
	assert.Equal(t, "MODERATE", result)

	rating = 7.0
	result = Rating(rating)
	assert.Equal(t, "HIGH", result)

	rating = 9.0
	result = Rating(rating)
	assert.Equal(t, "CRITICAL", result)
}

func TestAdjustSummary(t *testing.T) {
	summary := models.Summary{}

	AdjustSummary("CRITICAL", &summary)
	AdjustSummary("HIGH", &summary)
	AdjustSummary("MODERATE", &summary)
	AdjustSummary("LOW", &summary)
	AdjustSummary("UNSPECIFIED", &summary)

	assert.Equal(t, summary.Critical, 1)
	assert.Equal(t, summary.High, 1)
	assert.Equal(t, summary.Moderate, 1)
	assert.Equal(t, summary.Low, 1)
	assert.Equal(t, summary.Unspecified, 1)

	AdjustSummary("UNSPECIFIED", &summary)
	assert.Equal(t, summary.Unspecified, 2)
}
