package lib

import (
	"bytes"
	"encoding/json"
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

func Load(afs *afero.Afero, args []string) (purls []string, err error) {
	for _, arg := range args {
		isDir, _ := afs.IsDir(arg)
		if isDir {
			values, err := loadFolderPurls(afs, arg)
			if err != nil {
				return nil, nil
			}
			purls = append(purls, values...)
		} else {
			purls, err = loadFilePurls(afs, arg)
		}
		purls = slices.RemoveDuplicates(purls)
	}
	return
}

func loadFolderPurls(afs *afero.Afero, arg string) (purls []string, err error) {
	absPath, err := filepath.Abs(arg)
	if err != nil {
		return nil, err
	}
	files, err := afs.ReadDir(absPath)
	for _, file := range files {
		path := filepath.Join(absPath, file.Name())
		values, err := loadFilePurls(afs, path)
		if err != nil {
			log.Println(path, err)
		}
		purls = append(purls, values...)
	}
	return
}

func loadFilePurls(afs *afero.Afero, arg string) (purls []string, err error) {
	log.Printf("Reading: %v", arg)
	b, err := afs.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(b, []byte("\"bomFormat\": \"CycloneDX\",")) {
		log.Println("Detected CycloneDX")
		var sbom cyclone.BOM
		err = json.Unmarshal(b, &sbom)
		return cyclonedx.Purls(&sbom), err
		//} else if bytes.Contains(b, []byte("\"SPDXID\": \"SPDXRef-DOCUMENT\",")) {
	} else if bytes.Contains(b, []byte("{\"SPDXID\"")) {
		log.Println("Detected SPDX")
		var sbom spdx.BOM
		_ = json.Unmarshal(b, &sbom)
		return sbom.Purls(), err
	} else if bytes.Contains(b, []byte("\"url\": \"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-3.3.2.json\"")) {
		log.Println("Detected Syft")
		var sbom syft.BOM
		err = json.Unmarshal(b, &sbom)
		return sbom.Purls(), err
	}
	log.Printf("WARNING: %v doesn't look like an SBOM", arg)
	return nil, fmt.Errorf("%v is not an SBOM recognized by bomber", arg)
}
