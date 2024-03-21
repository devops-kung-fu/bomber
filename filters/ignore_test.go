package filters

import (
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/devops-kung-fu/bomber/models"
)

func TestIgnore(t *testing.T) {
	ignoreList := []string{"CVE-123", "CVE-456"}
	vulns := []models.Vulnerability{
		{
			ID:          "CVE-123", //should be removed
			Description: "Test 1",
		},
		{
			ID:          "CVE-789",
			Description: "Test 2",
		},
	}
	result := Ignore(vulns, ignoreList)
	assert.Len(t, result, 1)

	moreVulns := []models.Vulnerability{
		{
			ID:          "CVE-321",
			Description: "Test 3",
		},
		{
			ID:          "CVE-987",
			Description: "Test 4",
		},
		{
			ID:          "CVE-456", //should be removed
			Description: "Test 5",
		},
	}

	vulns = append(vulns, moreVulns...)
	result = Ignore(vulns, ignoreList)
	assert.Len(t, result, 3)

	for _, v := range result {
		assert.NotEqual(t, "CVE-123", v.ID)
		assert.NotEqual(t, "CVE-456", v.ID)
	}
}
