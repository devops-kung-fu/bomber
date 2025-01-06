package gad

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestInfo(t *testing.T) {
	provider := Provider{}
	info := provider.Info()
	assert.Equal(t, "GitHub Advisory Database (https://github.com/advisories)", info)
}

func TestProvider_SupportedEcosystems(t *testing.T) {
	provider := Provider{}
	expectedEcosystems := []string{
		"github-actions",
		"composer",
		"erlang",
		"golang",
		"maven",
		"npm",
		"nuget",
		"pypi",
		"rubygems",
		"cargo",
	}
	actualEcosystems := provider.SupportedEcosystems()
	assert.True(t, reflect.DeepEqual(expectedEcosystems, actualEcosystems), "Expected %v but got %v", expectedEcosystems, actualEcosystems)
}
