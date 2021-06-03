// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"strings"
)

func (m *composer) getProjectInfo(path string) (models.Module, error) {
	if err := m.buildCmd(projectInfoCmd, path); err != nil {
		return models.Module{}, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return models.Module{}, err
	}
	defer buffer.Reset()

	var projectInfo ComposerProjectInfo

	err := json.NewDecoder(buffer).Decode(&projectInfo)
	if err != nil {
		return models.Module{}, err
	}
	if projectInfo.Name == "" {
		return models.Module{}, errRootProject
	}

	module, err := convertProjectInfoToModule(projectInfo, path)
	if err != nil {
		return models.Module{}, err
	}

	return module, nil
}

func convertProjectInfoToModule(project ComposerProjectInfo, path string) (models.Module, error) {
	version := normalizePackageVersion(project.Versions[0])
	packageUrl := genComposerUrl(project.Name, version)
	checkSumValue := readCheckSum(packageUrl)
	name := getName(project.Name)
	module := models.Module{
		Name:       name,
		Version:    version,
		Root:       true,
		PackageURL: packageUrl,
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     checkSumValue,
		},
	}

	licensePkg, err := helper.GetLicenses(path)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	}

	return module, nil
}

func (m *composer) getTreeListFromComposerShowTree(path string) (ComposerTreeList, error) {
	if err := m.buildCmd(ShowModulesCmd, path); err != nil {
		return ComposerTreeList{}, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return ComposerTreeList{}, err
	}
	defer buffer.Reset()

	var tree ComposerTreeList
	err := json.NewDecoder(buffer).Decode(&tree)
	if err != nil {
		return ComposerTreeList{}, err
	}

	return tree, nil
}

func addTreeComponentsToModule(treeComponent ComposerTreeComponent, modules []models.Module) bool {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}
	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
	}

	rootLevelName := getName(treeComponent.Name)
	_, ok := moduleMap[rootLevelName]
	if !ok {
		return false
	}

	requires := treeComponent.Requires

	if requires == nil {
		return false
	}

	if len(requires) == 0 {
		return false
	}

	for _, subTreeComponent := range requires {
		childLevelName := getName(subTreeComponent.Name)
		childLevelModule, ok := moduleMap[childLevelName]
		if !ok {
			continue
		}

		addSubModuleToAModule(modules, moduleIndex[rootLevelName], childLevelModule)
		addTreeComponentsToModule(subTreeComponent, modules)
	}

	return true
}

func addSubModuleToAModule(modules []models.Module, moduleIndex int, subModule models.Module) {
	modules[moduleIndex].Modules[subModule.Name] = &models.Module{
		Name:             subModule.Name,
		Version:          subModule.Version,
		Path:             subModule.Path,
		LocalPath:        subModule.LocalPath,
		Supplier:         subModule.Supplier,
		PackageURL:       subModule.PackageURL,
		CheckSum:         subModule.CheckSum,
		PackageHomePage:  subModule.PackageHomePage,
		LicenseConcluded: subModule.LicenseConcluded,
		LicenseDeclared:  subModule.LicenseDeclared,
		CommentsLicense:  subModule.CommentsLicense,
		OtherLicense:     subModule.OtherLicense,
		Copyright:        subModule.Copyright,
		PackageComment:   subModule.PackageComment,
		Root:             subModule.Root,
	}
}

func getComposerLockFileData() (ComposerLockFile, error) {

	raw, err := ioutil.ReadFile(COMPOSER_LOCK_FILE_NAME)
	if err != nil {
		return ComposerLockFile{}, err
	}

	var fileData ComposerLockFile
	err = json.Unmarshal(raw, &fileData)
	if err != nil {
		return ComposerLockFile{}, err
	}
	return fileData, nil
}

func (m *composer) getModulesFromComposerLockFile(path string) ([]models.Module, error) {

	modules := make([]models.Module, 0)

	info, err := getComposerLockFileData()
	if err != nil {
		return nil, err
	}

	mainMod, err := m.getProjectInfo(path)
	if err != nil {
		return nil, err
	}

	modules = append(modules, mainMod)

	if len(info.Packages) > 0 {
		for _, pckg := range info.Packages {
			mod := convertLockPackageToModule(pckg)
			modules = append(modules, mod)
		}
	}

	if len(info.PackagesDev) > 0 {
		for _, pckg := range info.PackagesDev {
			mod := convertLockPackageToModule(pckg)
			modules = append(modules, mod)
		}
	}

	return modules, nil
}

func convertLockPackageToModule(dep ComposerLockPackage) models.Module {

	module := models.Module{
		Version:    normalizePackageVersion(dep.Version),
		Name:       getName(dep.Name),
		Root:       false,
		PackageURL: genUrlFromComposerPackage(dep),
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     getCheckSumValue(dep),
		},
		Supplier:  getAuthor(dep),
		LocalPath: getLocalPath(dep),
		Modules:   map[string]*models.Module{},
	}
	path := getLocalPath(dep)
	licensePkg, err := helper.GetLicenses(path)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	}

	return module
}

func getAuthor(dep ComposerLockPackage) models.SupplierContact {

	authors := dep.Authors
	if len(authors) == 0 {
		return models.SupplierContact{}
	}
	author := authors[0]
	pckAuthor := models.SupplierContact{
		Name:  author.Name,
		Email: author.Email,
	}
	return pckAuthor
}

func getName(moduleName string) string {
	s := strings.Split(moduleName, "/")

	if len(s) > 1 {
		return s[1]
	}

	return s[0]
}

func genUrlFromComposerPackage(dep ComposerLockPackage) string {
	URL := dep.Dist.URL
	if URL != "" {
		return URL
	}

	return genComposerUrl(dep.Name, dep.Version)
}
func genComposerUrl(name string, version string) string {
	return "https://github.com/" + name + ".git"
}

func normalizePackageVersion(version string) string {
	parts := strings.Split(version, "v")

	if parts[0] != "" {
		return version
	}

	if len(parts) > 1 {
		return parts[1]
	}

	return parts[0]
}

func getCheckSumValue(module ComposerLockPackage) string {
	value := module.Dist.Shasum
	if value != "" {
		return value
	}

	return readCheckSum(genUrlFromComposerPackage(module))
}

func readCheckSum(content string) string {
	if content == "" {
		return ""
	}
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func getLocalPath(module ComposerLockPackage) string {
	path := "./vendor/" + module.Name
	return path
}
