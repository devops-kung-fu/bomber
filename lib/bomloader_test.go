package lib

import (
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	spdx "github.com/devops-kung-fu/bomber/formats/spdx"
)

func TestLoad_cyclonedx(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/test-cyclonedx.json", cyclonedx.CycloneDXTestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)
	purls, err := Load(afs, []string{"/"})
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_SPDX(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/test-spdx.json", spdx.SPDXTestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)
	purls, err := Load(afs, []string{"/"})
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_garbage(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/not-a-sbom.json", []byte("test"), 0644)
	assert.NoError(t, err)

	_, err = loadFilePurls(afs, "/not-a-sbom.json")
	assert.Error(t, err)
	assert.Equal(t, "/not-a-sbom.json is not an SBOM recognized by bomber", err.Error())
}

func Test_loadFilePurls(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	_, err := loadFilePurls(afs, "no-file.json")
	assert.Error(t, err)
}

func spdxTestBytes() []byte {
	spdxString := `
	
	`
	return []byte(spdxString)
}
