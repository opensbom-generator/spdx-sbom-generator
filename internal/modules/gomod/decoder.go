// SPDX-License-Identifier: Apache-2.0

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

// ConvertPlainReaderToModules...
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
		//var m models.Module
		var m MOD
		if err := decoder.Decode(&m); err != nil {
			if err == io.EOF {
				break
			}

			return err
		}

		md, err := buildModule(&m)
		if err != nil {
			return err
		}

		md.Root = isRoot
		isRoot = false
		*modules = append(*modules, *md)
	}

	return nil
}

func buildModule(m *MOD) (*models.Module, error) {
	var module models.Module
	module.Name = helper.BuildModuleName(m.Path, m.Replace.Path, m.Replace.Dir)
	module.Version = m.Version
	module.LocalPath = m.Dir
	module.PackageURL = m.Path
	contentCheckSum := helper.BuildManifestContent(m.Dir)
	module.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA256,
		Content:   contentCheckSum,
	}
	licensePkg, err := helper.GetLicenses(m.Dir)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
		if !helper.LicenseSPDXExists(licensePkg.ID) {
			licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
			licensePkg.ExtractedText = fmt.Sprintf("<text>%s</text>", licensePkg.ExtractedText)
			module.OtherLicense = append(module.OtherLicense, licensePkg)
		}
	}
	module.Modules = map[string]*models.Module{}
	return &module, nil
}

func readMod(token string) ([]string, error) {
	mods := strings.Fields(strings.TrimSpace(token))
	if len(mods) != 2 {
		return nil, errFailedtoReadMod
	}

	return mods, nil

}
