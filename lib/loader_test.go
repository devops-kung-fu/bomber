package lib

import (
	"os"
	"testing"

	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	spdx "github.com/devops-kung-fu/bomber/formats/spdx"
	syft "github.com/devops-kung-fu/bomber/formats/syft"
)

func TestLoad_cyclonedx(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/test-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)

	scanned, purls, _, err := Load(afs, []string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_cyclonedx_stdin(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	tmpfile, err := os.CreateTemp("", "test-cyclonedx.json")
	assert.NoError(t, err)

	defer os.Remove(tmpfile.Name()) // clean up

	_, err = tmpfile.Write(cyclonedx.TestBytes())
	assert.NoError(t, err)

	_, err = tmpfile.Seek(0, 0)
	assert.NoError(t, err)

	oldStdin := os.Stdin
	defer func() { os.Stdin = oldStdin }() // Restore original Stdin

	os.Stdin = tmpfile

	scanned, purls, _, err := Load(afs, []string{"-"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	err = tmpfile.Close()
	assert.NoError(t, err)
}

func TestLoad_SPDX(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/test-spdx.json", spdx.TestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)
	scanned, purls, _, err := Load(afs, []string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_syft(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/test-syft.json", syft.TestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)
	scanned, purls, _, err := Load(afs, []string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_BadJSON_SPDX(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	fudgedFile := spdx.TestBytes()
	bogusString := "bogus"
	fudgedFile = append(fudgedFile, bogusString...)

	err := afs.WriteFile("/test-spdx.json", fudgedFile, 0644)
	assert.NoError(t, err)

	_, _, _, err = loadFilePurls(afs, "/test-spdx.json")
	assert.Error(t, err)
	assert.Equal(t, "/test-spdx.json is not a SBOM recognized by bomber", err.Error())
}

func TestLoad_garbage(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/not-a-sbom.json", []byte("test"), 0644)
	assert.NoError(t, err)

	_, _, _, err = loadFilePurls(afs, "/not-a-sbom.json")
	assert.Error(t, err)
	assert.Equal(t, "/not-a-sbom.json is not a SBOM recognized by bomber", err.Error())
}

func Test_loadFilePurls(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	_, _, _, err := loadFilePurls(afs, "no-file.json")
	assert.Error(t, err)
}

func TestLoad_multiple_cyclonedx(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	err := afs.WriteFile("/test-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	err = afs.WriteFile("/test1/test1-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	err = afs.WriteFile("/test2/test2-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	scanned, purls, _, err := Load(afs, []string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoadIgnore(t *testing.T) {
	afs := &afero.Afero{Fs: afero.NewMemMapFs()}

	afs.WriteFile("test.ignore", []byte("test\ntest2"), 0644)

	cves, err := LoadIgnore(afs, "test.ignore")
	assert.NoError(t, err)
	assert.Len(t, cves, 2)

	_, err = LoadIgnore(afs, "tst.ignore")
	assert.Error(t, err)
}
