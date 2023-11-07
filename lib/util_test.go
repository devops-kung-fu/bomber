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

func TestParseSeverity(t *testing.T) {
	t.Run("Valid severity: low", func(t *testing.T) {
		severity := "low"
		expected := 11
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: moderate", func(t *testing.T) {
		severity := "moderate"
		expected := 12
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: high", func(t *testing.T) {
		severity := "high"
		expected := 13
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Valid severity: critical", func(t *testing.T) {
		severity := "critical"
		expected := 14
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Invalid severity: undefined", func(t *testing.T) {
		severity := "invalid"
		expected := 0
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})

	t.Run("Mixed case severity: moderate", func(t *testing.T) {
		severity := "MoDerAte"
		expected := 12
		result := ParseSeverity(severity)
		assert.Equal(t, expected, result)
	})
}
