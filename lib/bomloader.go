package lib

import (
	"bytes"
	"encoding/json"
	"log"
	"path/filepath"

	cyclone "github.com/CycloneDX/cyclonedx-go"
	"github.com/spf13/afero"

	"github.com/devops-kung-fu/bomber/cyclonedx"
	"github.com/devops-kung-fu/bomber/spdx"
	"github.com/devops-kung-fu/bomber/syft"
)

func Load(afs *afero.Afero, args []string) (purls []string, err error) {
	for _, arg := range args {
		isDir, _ := afs.IsDir(arg)
		if isDir {
			values, err := loadFolderPurls(afs, arg)
			if err != nil {
				return nil, err
			}
			purls = append(purls, values...)
		} else {
			purls, err = loadFilePurls(afs, arg)
		}
		purls = removeDuplicates(purls)
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
	b, err := afs.ReadFile(arg)
	if err != nil {
		return nil, err
	}
	if bytes.Contains(b, []byte("\"bomFormat\": \"CycloneDX\",")) {
		var sbom cyclone.BOM
		err = json.Unmarshal(b, &sbom)
		return cyclonedx.Purls(&sbom), err
	} else if bytes.Contains(b, []byte("\"SPDXID\": \"SPDXRef-DOCUMENT\",")) {
		var sbom spdx.BOM
		_ = json.Unmarshal(b, &sbom)
		return sbom.Purls(), err
	} else if bytes.Contains(b, []byte("\"url\": \"https://raw.githubusercontent.com/anchore/syft/main/schema/json/schema-3.3.2.json\"")) {
		var sbom syft.BOM
		err = json.Unmarshal(b, &sbom)
		return sbom.Purls(), err
	}
	return
}

func removeDuplicates[T string | int](sliceList []T) []T {
	allKeys := make(map[T]bool)
	list := []T{}
	for _, item := range sliceList {
		if _, value := allKeys[item]; !value {
			allKeys[item] = true
			list = append(list, item)
		}
	}
	return list
}
