// SPDX-License-Identifier: Apache-2.0

package cargo

import (
	"encoding/json"
	"net/mail"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"strings"
)

func addDepthModules(modules []models.Module, cargoPackages []CargoPackage) error {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}
	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
	}

	for _, cargoPackage := range cargoPackages {

		rootLevelName := cargoPackage.Name
		rootModuleIndex, ok := moduleIndex[rootLevelName]
		if !ok {
			continue
		}

		cargoDependencies := cargoPackage.Dependencies
		if len(cargoDependencies) == 0 {
			continue
		}

		for _, cargoDep := range cargoDependencies {
			subModuleName := cargoDep.Name
			subModule, ok := moduleMap[subModuleName]
			if !ok {
				continue
			}

			modules[rootModuleIndex].Modules[subModuleName] = &models.Module{
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

	}

	return nil
}

func convertMetadataToModulesList(cargoPackages []CargoPackage) ([]models.Module, error) {

	var collection []models.Module

	for _, dep := range cargoPackages {
		module := convertCargoPackageToModule(dep)
		collection = append(collection, module)
	}

	return collection, nil
}

func convertCargoPackageToModule(dep CargoPackage) models.Module {
	localPath := convertToLocalPath(dep.ManifestPath)

	module := models.Module{
		Version:    dep.Version,
		Name:       dep.Name,
		Root:       false,
		PackageURL: getPackageURL(dep),
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(dep.ID),
		},
		LocalPath:       localPath,
		PackageHomePage: dep.Homepage,
		Supplier:        getSupplier(dep.Authors),
		Modules:         map[string]*models.Module{},
	}

	licensePkg, err := helper.GetLicenses(localPath)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	}

	return module
}

func getSupplier(authors []string) models.SupplierContact {

	if len(authors) == 0 {
		return models.SupplierContact{}
	}

	mainAuthor := authors[0]
	author, err := mail.ParseAddress(mainAuthor)
	if err != nil {
		return models.SupplierContact{
			Name: mainAuthor,
		}
	}
	supplier := models.SupplierContact{
		Name:  author.Name,
		Email: author.Address,
	}
	return supplier
}

func (m *mod) getRootModule(path string) (models.Module, error) {
	name := m.getRootProjectName(path)
	cargoMetadata, err := m.getCargoMetadata(path)
	if err != nil {
		return models.Module{}, err
	}

	packages := cargoMetadata.Packages
	rootPackage, _ := findPackageByName(packages, name)
	mod := convertCargoPackageToPluginModule(rootPackage)
	return mod, nil
}

func convertCargoPackageToPluginModule(dep CargoPackage) models.Module {

	localPath := convertToLocalPath(dep.ManifestPath)

	module := models.Module{
		Version:    dep.Version,
		Name:       dep.Name,
		Root:       true,
		PackageURL: getPackageURL(dep),
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(dep.ID),
		},
		LocalPath:       localPath,
		PackageHomePage: removeURLProtocol(dep.Homepage),
		Supplier:        getSupplier(dep.Authors),
		Modules:         map[string]*models.Module{},
	}

	licensePkg, err := helper.GetLicenses(localPath)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	}

	return module
}

func convertToLocalPath(manifestPath string) string {
	localPath := strings.ReplaceAll(manifestPath, "/Cargo.toml", "")
	return localPath
}

func getPackageURL(dep CargoPackage) string {
	var value string
	if dep.Source != "" {
		value = dep.Source
	} else {
		value = dep.Repository
	}

	value = removeURLProtocol(value)

	return value
}

func (m *mod) getCargoMetadata(path string) (CargoMetadata, error) {

	if m.cargoMetadata.WorkspaceRoot != "" {
		return m.cargoMetadata, nil
	}

	buff, _ := m.runTask(ModulesCmd, path)
	defer buff.Reset()

	var cargoMetadata CargoMetadata
	if err := json.NewDecoder(buff).Decode(&cargoMetadata); err != nil {
		return CargoMetadata{}, err
	}
	m.cargoMetadata = cargoMetadata

	return m.cargoMetadata, nil
}

func (m *mod) getRootProjectName(path string) string {
	err := m.buildCmd(RootModuleNameCmd, path)
	if err != nil {
		return ""
	}

	pckidRoot, err := m.command.Output()
	if err != nil {
		return ""
	}
	parts := strings.Split(pckidRoot, "/")
	lastpart := parts[len(parts)-1]
	lastpart = strings.ReplaceAll(lastpart, "\n", "")

	rootNameParts := strings.Split(lastpart, "#")
	name := rootNameParts[0]

	return name
}

func findPackageByName(packages []CargoPackage, name string) (CargoPackage, bool) {

	for _, mod := range packages {
		if mod.Name == name {
			return mod, true
		}
	}

	return CargoPackage{}, false
}
