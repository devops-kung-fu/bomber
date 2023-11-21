// Package lib contains core functionality to load Software Bill of Materials and contains common functions
package lib

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/devops-kung-fu/common/slices"
	"github.com/spf13/afero"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	spdx "github.com/devops-kung-fu/bomber/formats/spdx"
	syft "github.com/devops-kung-fu/bomber/formats/syft"
	"github.com/devops-kung-fu/bomber/models"
)

type Loader struct {
	Afs *afero.Afero
}

// Load retrieves a slice of Purls from various types of SBOMs
func (l *Loader) Load(args []string) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	for _, arg := range args {
		isDir, _ := l.Afs.IsDir(arg)
		if isDir {
			s, values, lic, err := l.loadFolderPurls(arg)
			if err != nil {
				return scanned, nil, nil, err
			}
			scanned = append(scanned, s...)
			purls = append(purls, values...)
			licenses = append(licenses, lic...)
		} else {
			scanned, purls, licenses, err = l.loadFilePurls(arg)
		}
		purls = slices.RemoveDuplicates(purls)
		licenses = slices.RemoveDuplicates(licenses)
	}
	return
}

func (l *Loader) loadFolderPurls(arg string) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	absPath, err := filepath.Abs(arg)
	if err != nil {
		return scanned, nil, nil, err
	}
	files, err := l.Afs.ReadDir(absPath)
	for _, file := range files {
		path := filepath.Join(absPath, file.Name())
		s, values, lic, err := l.loadFilePurls(path)
		if err != nil {
			log.Println(path, err)
		}
		scanned = append(scanned, s...)
		purls = append(purls, values...)
		licenses = append(licenses, lic...)
	}
	return
}

func (l *Loader) loadFilePurls(arg string) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	b, err := l.readFile(arg)
	if err != nil {
		return scanned, nil, nil, err
	}

	scanned = append(scanned, models.ScannedFile{
		Name:   arg,
		SHA256: fmt.Sprintf("%x", sha256.Sum256(b)),
	})

	if l.isCycloneDXXML(b) {
		log.Println("Detected CycloneDX XML")
		return l.processCycloneDX(cyclone.BOMFileFormatXML, b, scanned)
	} else if l.isCycloneDXJSON(b) {
		log.Println("Detected CycloneDX JSON")
		return l.processCycloneDX(cyclone.BOMFileFormatJSON, b, scanned)
	} else if l.isSPDX(b) {
		log.Println("Detected SPDX")
		var sbom spdx.BOM
		if err = json.Unmarshal(b, &sbom); err == nil {
			return scanned, sbom.Purls(), sbom.Licenses(), err
		}
	} else if l.isSyft(b) {
		log.Println("Detected Syft")
		var sbom syft.BOM
		if err = json.Unmarshal(b, &sbom); err == nil {
			return scanned, sbom.Purls(), sbom.Licenses(), err
		}
	}

	log.Printf("WARNING: %v isn't a valid SBOM", arg)
	log.Println(err)
	return scanned, nil, nil, fmt.Errorf("%v is not a SBOM recognized by bomber", arg)
}

func (l *Loader) readFile(arg string) ([]byte, error) {
	if arg == "-" {
		log.Printf("Reading from stdin")
		return io.ReadAll(bufio.NewReader(os.Stdin))
	}
	log.Printf("Reading: %v", arg)
	return l.Afs.ReadFile(arg)
}

func (l *Loader) isCycloneDXXML(b []byte) bool {
	return bytes.Contains(b, []byte("xmlns")) && bytes.Contains(b, []byte("CycloneDX"))
}

func (l *Loader) isCycloneDXJSON(b []byte) bool {
	return bytes.Contains(b, []byte("bomFormat")) && bytes.Contains(b, []byte("CycloneDX"))
}

func (l *Loader) isSPDX(b []byte) bool {
	return bytes.Contains(b, []byte("SPDXRef-DOCUMENT"))
}

func (l *Loader) isSyft(b []byte) bool {
	return bytes.Contains(b, []byte("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-"))
}

func (l *Loader) processCycloneDX(format cyclone.BOMFileFormat, b []byte, s []models.ScannedFile) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	var sbom cyclone.BOM

	reader := bytes.NewReader(b)
	decoder := cyclone.NewBOMDecoder(reader, format)
	err = decoder.Decode(&sbom)
	if err == nil {
		return s, cyclonedx.Purls(&sbom), cyclonedx.Licenses(&sbom), err
	}
	return
}

// LoadIgnore loads a list of CVEs entered one on each line from the filename
func (l *Loader) LoadIgnore(ignoreFile string) (cves []string, err error) {
	f, err := l.Afs.Open(ignoreFile)
	if err != nil {
		log.Printf("error opening ignore: %v\n", err)
		return
	}
	defer func() {
		_ = f.Close()
	}()

	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		cves = append(cves, scanner.Text())
	}

	return
}
