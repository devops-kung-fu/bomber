// Package lib contains core functionality to load Software Bill of Materials and contains common functions
package lib

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
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

// Load retrieves a slice of Purls from various types of SBOMs
func Load(afs *afero.Afero, args []string) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	for _, arg := range args {
		isDir, _ := afs.IsDir(arg)
		if isDir {
			s, values, lic, err := loadFolderPurls(afs, arg)
			if err != nil {
				return scanned, nil, nil, err
			}
			scanned = append(scanned, s...)
			purls = append(purls, values...)
			licenses = append(licenses, lic...)
		} else {
			scanned, purls, licenses, err = loadFilePurls(afs, arg)
		}
		purls = slices.RemoveDuplicates(purls)
		licenses = slices.RemoveDuplicates(licenses)
	}
	return
}

func loadFolderPurls(afs *afero.Afero, arg string) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	absPath, err := filepath.Abs(arg)
	if err != nil {
		return scanned, nil, nil, err
	}
	files, err := afs.ReadDir(absPath)
	for _, file := range files {
		path := filepath.Join(absPath, file.Name())
		s, values, lic, err := loadFilePurls(afs, path)
		if err != nil {
			log.Println(path, err)
		}
		scanned = append(scanned, s...)
		purls = append(purls, values...)
		licenses = append(licenses, lic...)
	}
	return
}

func loadFilePurls(afs *afero.Afero, arg string) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	b, err := readFile(afs, arg)
	if err != nil {
		return scanned, nil, nil, err
	}

	scanned = append(scanned, models.ScannedFile{
		Name:   arg,
		SHA256: fmt.Sprintf("%x", sha256.Sum256(b)),
	})

	if isCycloneDXXML(b) {
		log.Println("Detected CycloneDX XML")
		return processCycloneDX(b, scanned, xml.Unmarshal)
	} else if isCycloneDXJSON(b) {
		log.Println("Detected CycloneDX JSON")
		return processCycloneDX(b, scanned, json.Unmarshal)
	} else if isSPDX(b) {
		log.Println("Detected SPDX")
		var sbom spdx.BOM
		if err = json.Unmarshal(b, &sbom); err == nil {
			return scanned, sbom.Purls(), sbom.Licenses(), err
		}
	} else if isSyft(b) {
		log.Println("Detected Syft")
		var sbom syft.BOM
		if err = json.Unmarshal(b, &sbom); err == nil {
			return scanned, sbom.Purls(), sbom.Licenses(), err
		}
	}

	log.Printf("WARNING: %v isn't a valid SBOM", arg)
	return scanned, nil, nil, fmt.Errorf("%v is not a SBOM recognized by bomber", arg)
}

func readFile(afs *afero.Afero, arg string) ([]byte, error) {
	if arg == "-" {
		log.Printf("Reading from stdin")
		return io.ReadAll(bufio.NewReader(os.Stdin))
	}
	log.Printf("Reading: %v", arg)
	return afs.ReadFile(arg)
}

func isCycloneDXXML(b []byte) bool {
	return bytes.Contains(b, []byte("xmlns")) && bytes.Contains(b, []byte("CycloneDX"))
}

func isCycloneDXJSON(b []byte) bool {
	return bytes.Contains(b, []byte("bomFormat")) && bytes.Contains(b, []byte("CycloneDX"))
}

func isSPDX(b []byte) bool {
	return bytes.Contains(b, []byte("SPDXRef-DOCUMENT"))
}

func isSyft(b []byte) bool {
	return bytes.Contains(b, []byte("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-"))
}

func processCycloneDX(b []byte, s []models.ScannedFile, unmarshal func([]byte, interface{}) error) (scanned []models.ScannedFile, purls []string, licenses []string, err error) {
	var sbom cyclone.BOM
	if err = unmarshal(b, &sbom); err == nil {
		return s, cyclonedx.Purls(&sbom), cyclonedx.Licenses(&sbom), err
	}
	return
}

// LoadIgnore loads a list of CVEs entered one on each line from the filename
func LoadIgnore(afs *afero.Afero, ignoreFile string) (cves []string, err error) {
	f, err := afs.Open(ignoreFile)
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
