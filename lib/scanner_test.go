// Package lib contains core functionality to load Software Bill of Materials and contains common functions
package lib

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"
)

func Test_detectEcosystems(t *testing.T) {
	scanner := Scanner{}

	purls := []string{
		"pkg:golang/github.com/test/test1@v1.19.0",
		"pkg:npm/github.com/test/test2@v1.19.0",
		"invalid_url", // This should be ignored
	}

	result := scanner.detectEcosystems(purls)

	assert.ElementsMatch(t, []string{"golang", "npm"}, result, "Detected ecosystems do not match expected result")
}

func TestScanner_loadIgnoreData(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/.bomber.ignore", []byte("CVE-2022-31163"), 0644)
	assert.NoError(t, err)

	scanner := Scanner{}
	results, err := scanner.loadIgnoreData(afs, "/.bomber.ignore")

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, results[0], "CVE-2022-31163")

	_, err = scanner.loadIgnoreData(afs, "test")
	assert.Error(t, err)

	results, err = scanner.loadIgnoreData(afs, "")
	assert.NoError(t, err)
	assert.Len(t, results, 0)
}
