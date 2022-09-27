package lib

import (
	"bytes"
	"encoding/json"
	"encoding/xml"
	"fmt"
	"log"
	"path/filepath"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/devops-kung-fu/common/slices"
	"github.com/spf13/afero"

	cyclonedx "github.com/devops-kung-fu/bomber/formats/cyclonedx"
	spdx "github.com/devops-kung-fu/bomber/formats/spdx"
	syft "github.com/devops-kung-fu/bomber/formats/syft"
)

// Load retrieves a slice of Purls from various types of SBOMs
func Load(afs *afero.Afero, args []string) (purls []string, licenses []string, err error) {
	for _, arg := range args {
		isDir, _ := afs.IsDir(arg)
		if isDir {
			values, lic, err := loadFolderPurls(afs, arg)
			if err != nil {
				return nil, nil, err
			}
			purls = append(purls, values...)
			licenses = append(licenses, lic...)
		} else {
			purls, licenses, err = loadFilePurls(afs, arg)
		}
		purls = slices.RemoveDuplicates(purls)
		licenses = slices.RemoveDuplicates(licenses)
	}
	return
}

func loadFolderPurls(afs *afero.Afero, arg string) (purls []string, licenses []string, err error) {
	absPath, err := filepath.Abs(arg)
	if err != nil {
		return nil, nil, err
	}
	files, err := afs.ReadDir(absPath)
	for _, file := range files {
		path := filepath.Join(absPath, file.Name())
		values, lic, err := loadFilePurls(afs, path)
		if err != nil {
			log.Println(path, err)
		}
		purls = append(purls, values...)
		licenses = append(licenses, lic...)
	}
	return
}

func loadFilePurls(afs *afero.Afero, arg string) (purls []string, licenses []string, err error) {
	log.Printf("Reading: %v", arg)
	b, err := afs.ReadFile(arg)
	if err != nil {
		return nil, nil, err
	}
	if bytes.Contains(b, []byte("xmlns")) && bytes.Contains(b, []byte("http://cyclonedx.org/schema/bom/1.3")) {
		log.Println("Detected CycloneDX XML")
		var sbom cyclone.BOM
		err = xml.Unmarshal(b, &sbom)
		if err == nil {
			return cyclonedx.Purls(&sbom), cyclonedx.Licenses(&sbom), err
		}
	} else if bytes.Contains(b, []byte("\"bomFormat\": \"CycloneDX\",")) {
		log.Println("Detected CycloneDX JSON")
		var sbom cyclone.BOM
		err = json.Unmarshal(b, &sbom)
		if err == nil {
			return cyclonedx.Purls(&sbom), cyclonedx.Licenses(&sbom), err
		}
	} else if bytes.Contains(b, []byte("SPDXRef-DOCUMENT")) {
		log.Println("Detected SPDX")
		var sbom spdx.BOM
		err = json.Unmarshal(b, &sbom)
		if err == nil {
			return sbom.Purls(), sbom.Licenses(), err
		}
	} else if bytes.Contains(b, []byte("\"url\": \"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-3.3.2.json\"")) {
		log.Println("Detected Syft")
		var sbom syft.BOM
		err = json.Unmarshal(b, &sbom)
		if err == nil {
			return sbom.Purls(), sbom.Licenses(), err
		}
	}
	log.Printf("WARNING: %v isn't a valid SBOM", arg)
	return nil, nil, fmt.Errorf("%v is not an SBOM recognized by bomber", arg)
}
