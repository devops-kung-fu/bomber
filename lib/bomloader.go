package lib

import (
	"bufio"
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
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

	var b []byte

	if arg == "-" {
		log.Printf("Reading from stdin")
		b, err = ioutil.ReadAll(bufio.NewReader(os.Stdin))
	} else {
		log.Printf("Reading: %v", arg)
		b, err = afs.ReadFile(arg)
	}
	scanned = append(scanned, models.ScannedFile{
		Name:   arg,
		SHA256: fmt.Sprintf("%x", sha256.Sum256(b)),
	})
	if err != nil {
		return scanned, nil, nil, err
	}

	if bytes.Contains(b, []byte("xmlns")) && bytes.Contains(b, []byte("CycloneDX")) {
		log.Println("Detected CycloneDX XML")
		var sbom cyclone.BOM
		err = xml.Unmarshal(b, &sbom)
		if err == nil {
			return scanned, cyclonedx.Purls(&sbom), cyclonedx.Licenses(&sbom), err
		}
	} else if bytes.Contains(b, []byte("bomFormat")) && bytes.Contains(b, []byte("CycloneDX")) {
		log.Println("Detected CycloneDX JSON")
		var sbom cyclone.BOM
		err = json.Unmarshal(b, &sbom)
		if err == nil {
			return scanned, cyclonedx.Purls(&sbom), cyclonedx.Licenses(&sbom), err
		}
	} else if bytes.Contains(b, []byte("SPDXRef-DOCUMENT")) {
		log.Println("Detected SPDX")
		var sbom spdx.BOM
		err = json.Unmarshal(b, &sbom)
		if err == nil {
			return scanned, sbom.Purls(), sbom.Licenses(), err
		}
	} else if bytes.Contains(b, []byte("https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-")) {
		log.Println("Detected Syft")
		var sbom syft.BOM
		err = json.Unmarshal(b, &sbom)
		if err == nil {
			return scanned, sbom.Purls(), sbom.Licenses(), err
		}
	}
	log.Printf("WARNING: %v isn't a valid SBOM", arg)
	return scanned, nil, nil, fmt.Errorf("%v is not an SBOM recognized by bomber", arg)
}
