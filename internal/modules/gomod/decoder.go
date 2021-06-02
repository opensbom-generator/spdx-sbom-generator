<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
package gomod

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

var errFailedtoReadMod = errors.New("Failed to read go.mod line")

// Decoder
type Decoder struct {
	reader io.Reader
}

// NewDecoder ...
func NewDecoder(r io.Reader) *Decoder {
	return &Decoder{
		reader: r,
	}
}

// ConvertJSONReaderToModules ...
// todo: improve code below
func (d *Decoder) ConvertPlainReaderToModules(modules []models.Module) error {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}
	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
	}

	scanner := bufio.NewScanner(d.reader)
	for scanner.Scan() {
		mods, err := readMod(scanner.Text())
		if err != nil {
			return err
		}
		moduleName := strings.Split(mods[0], "@")[0]
		if _, ok := moduleMap[moduleName]; !ok {
			continue
		}

		depName := strings.Split(mods[1], "@")[0]
		depModule, ok := moduleMap[depName]
		if !ok {
			continue
		}

		modules[moduleIndex[moduleName]].Modules[depName] = &models.Module{
			Name:             depModule.Name,
			Version:          depModule.Version,
			Path:             depModule.Path,
			LocalPath:        depModule.LocalPath,
			Supplier:         depModule.Supplier,
			PackageURL:       depModule.PackageURL,
			CheckSum:         depModule.CheckSum,
			PackageHomePage:  depModule.PackageHomePage,
			LicenseConcluded: depModule.LicenseConcluded,
			LicenseDeclared:  depModule.LicenseDeclared,
			CommentsLicense:  depModule.CommentsLicense,
			OtherLicense:     depModule.OtherLicense,
			Copyright:        depModule.Copyright,
			PackageComment:   depModule.PackageComment,
			Root:             depModule.Root,
		}
	}

	return nil
}

// ConvertJSONReaderToModules ...
func (d *Decoder) ConvertJSONReaderToModules(modules *[]models.Module) error {
	decoder := json.NewDecoder(d.reader)
	isRoot := true
	for {
		var m models.Module
		if err := decoder.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}

			return err
		}

		if err := buildModule(&m); err != nil {
			return err
		}

		m.Root = isRoot
		isRoot = false
		*modules = append(*modules, m)
	}

	return nil
}

func buildModule(module *models.Module) error {
	module.Name = module.Path
	module.PackageURL = module.Path
	module.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     readCheckSum(module.Path),
	}
	licensePkg, err := helper.GetLicenses(module.LocalPath)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
		if !helper.LicenseSPDXExists(licensePkg.ID) {
			licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
<<<<<<< HEAD
			// figure out why other license always fails to validate SPDX
			//licensePkg.ExtractedText = fmt.Sprintf("<text>%s</text>", licensePkg.ExtractedText)
			//module.OtherLicense = append(module.OtherLicense, licensePkg)
=======
			licensePkg.ExtractedText = fmt.Sprintf("<text>%s</text>", licensePkg.ExtractedText)
			module.OtherLicense = append(module.OtherLicense, licensePkg)
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
		}
	}

	module.Modules = map[string]*models.Module{}
	return nil
}

func readMod(token string) ([]string, error) {
	mods := strings.Fields(strings.TrimSpace(token))
	if len(mods) != 2 {
		return nil, errFailedtoReadMod
	}

	return mods, nil

}
