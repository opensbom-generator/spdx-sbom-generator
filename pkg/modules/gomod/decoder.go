// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/go-git/go-git/v5"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

const vendorFolder = "vendor"

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
func (d *Decoder) ConvertJSONReaderToModules(path string, modules *[]models.Module) error {
	decoder := json.NewDecoder(d.reader)
	pathMap := map[string]bool{}
	for {
		//var m models.Module
		var j JSONOutput
		if err := decoder.Decode(&j); err != nil {
			if err == io.EOF {
				break
			}

			return err
		}

		// we will only use Module for now
		if j.Module == nil {
			continue
		}

		if _, ok := pathMap[j.Module.Path]; ok {
			continue
		}

		pathMap[j.Module.Path] = true
		md, err := buildModule(j.Module)
		if err != nil {
			return err
		}

		if j.Module.Path == path {
			md.Root = true
			md.PackageDownloadLocation = buildRootDownloadURL(md.LocalPath)
		}
		*modules = append(*modules, *md)
	}

	return nil
}

// ConvertJSONReaderToSingleModule ...
func (d *Decoder) ConvertJSONReaderToSingleModule(module *models.Module) error {
	err := json.NewDecoder(d.reader).Decode(module)
	if err == io.EOF {
		return nil
	}

	return err
}

func buildModule(m *Module) (*models.Module, error) {
	localDir := buildLocalPath(m.Path, m.Dir)
	contentCheckSum := helper.BuildManifestContent(localDir)
	module := models.Module{
		Name:                    helper.BuildModuleName(m.Path, m.Replace.Path, m.Replace.Dir),
		Version:                 m.Version,
		LocalPath:               localDir,
		PackageURL:              m.Path,
		PackageDownloadLocation: buildDownloadURL(m.Path, m.Version),
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA256,
			Content:   contentCheckSum,
		},
		Supplier: models.SupplierContact{
			Type: models.Organization,
			Name: helper.BuildModuleName(m.Path, m.Replace.Path, m.Replace.Dir),
		},
	}
	licensePkg, err := helper.GetLicenses(localDir)
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

func buildLocalPath(path, dir string) string {
	cd, err := os.Getwd()
	if err != nil {
		return dir
	}

	localPath := filepath.Join(cd, vendorFolder, path)
	if helper.Exists(localPath) {
		return localPath
	}

	return dir
}

// buildRootDownloadURL only support origin for now
// todo: figure out a valid git value
func buildRootDownloadURL(localPath string) string {
	localGit, err := git.PlainOpen(localPath)
	if err != nil {
		return ""
	}

	remote, err := localGit.Remote("origin")
	if err != nil {
		return ""
	}

	config := remote.Config()
	if err := config.Validate(); err != nil {
		return ""
	}

	url := config.URLs[0]
	// let's convert git@gitxxx format to https
	if strings.HasPrefix(url, "git@") {
		re := strings.NewReplacer("git@", "https://", ":", "/")
		url = re.Replace(url)
	}

	return fmt.Sprintf("git+%s", url)
}

func buildDownloadURL(path, version string) string {
	if strings.HasPrefix(path, "github.com") {
		if version != "" {
			return fmt.Sprintf("https://%s/releases/tag/%s", path, version)
		}

		return fmt.Sprintf("git+https://%s.git", path)
	}

	return fmt.Sprintf("https://%s", path)
}
