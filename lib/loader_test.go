package lib

import (
	"os"
	"testing"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/afero"
	"github.com/stretchr/testify/assert"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	spdx "github.com/devops-kung-fu/bomber/formats/spdx"
	syft "github.com/devops-kung-fu/bomber/formats/syft"
)

var (
	afs *afero.Afero
	l   Loader
)

func SetupTest() {
	afs = &afero.Afero{Fs: afero.NewMemMapFs()}
	l = Loader{Afs: afs}
}

func Test_Load_cyclonedx(t *testing.T) {
	SetupTest()
	err := afs.WriteFile("/test-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)

	scanned, purls, _, err := l.Load([]string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_cyclonedx_stdin(t *testing.T) {
	SetupTest()
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

	scanned, purls, _, err := l.Load([]string{"-"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	err = tmpfile.Close()
	assert.NoError(t, err)
}

func Test_Load_SPDX(t *testing.T) {
	SetupTest()
	err := afs.WriteFile("/test-spdx.json", spdx.TestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)

	scanned, purls, _, err := l.Load([]string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func TestLoad_syft(t *testing.T) {
	SetupTest()
	err := afs.WriteFile("/test-syft.json", syft.TestBytes(), 0644)
	assert.NoError(t, err)

	files, _ := afs.ReadDir("/")
	assert.Len(t, files, 1)

	scanned, purls, _, err := l.Load([]string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func Test_Load_BadJSON_SPDX(t *testing.T) {
	SetupTest()
	fudgedFile := spdx.TestBytes()
	bogusString := "bogus"
	fudgedFile = append(fudgedFile, bogusString...)

	err := afs.WriteFile("/test-spdx.json", fudgedFile, 0644)
	assert.NoError(t, err)

	_, _, _, err = l.loadFilePurls("/test-spdx.json")
	assert.Error(t, err)
	assert.Equal(t, "/test-spdx.json is not a SBOM recognized by bomber", err.Error())
}

func TestLoad_garbage(t *testing.T) {
	SetupTest()
	err := afs.WriteFile("/not-a-sbom.json", []byte("test"), 0644)
	assert.NoError(t, err)

	_, _, _, err = l.loadFilePurls("/not-a-sbom.json")
	assert.Error(t, err)
	assert.Equal(t, "/not-a-sbom.json is not a SBOM recognized by bomber", err.Error())
}

func Test_loadFilePurls(t *testing.T) {
	SetupTest()
	_, _, _, err := l.loadFilePurls("no-file.json")
	assert.Error(t, err)
}

func TestLoad_multiple_cyclonedx(t *testing.T) {
	SetupTest()
	err := afs.WriteFile("/test-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	err = afs.WriteFile("/test1/test1-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	err = afs.WriteFile("/test2/test2-cyclonedx.json", cyclonedx.TestBytes(), 0644)
	assert.NoError(t, err)

	scanned, purls, _, err := l.Load([]string{"/"})

	assert.NotNil(t, scanned)
	assert.NoError(t, err)
	assert.Len(t, purls, 1)
	assert.Equal(t, "pkg:golang/github.com/CycloneDX/cyclonedx-go@v0.6.0", purls[0])

	_, err = afs.ReadDir("/bad-dir")
	assert.Error(t, err)
}

func Test_LoadIgnore(t *testing.T) {
	SetupTest()
	afs.WriteFile("test.ignore", []byte("test\ntest2"), 0644)

	cves, err := l.LoadIgnore("test.ignore")
	assert.NoError(t, err)
	assert.Len(t, cves, 2)

	_, err = l.LoadIgnore("tst.ignore")
	assert.Error(t, err)
}

func Test_LoadIgnoreData(t *testing.T) {
	SetupTest()

	err := afs.WriteFile("/.bomber.ignore", []byte("CVE-2022-31163"), 0644)
	assert.NoError(t, err)

	results, err := l.LoadIgnore("/.bomber.ignore")

	assert.NoError(t, err)
	assert.Len(t, results, 1)
	assert.Equal(t, results[0], "CVE-2022-31163")

	_, err = l.LoadIgnore("test")
	assert.Error(t, err)

	results, err = l.LoadIgnore("")
	assert.NoError(t, err)
	assert.Len(t, results, 0)
}

func Test_ProcessCycloneDX_InvalidFormat(t *testing.T) {

	invalidFile := []byte("{{")

	loader := Loader{}

	_, _, _, err := loader.processCycloneDX(
		cyclone.BOMFileFormatJSON,
		invalidFile,
		nil,
	)

	assert.Error(t, err)
}
