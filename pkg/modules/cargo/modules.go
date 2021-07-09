// SPDX-License-Identifier: Apache-2.0

package cargo

import (
	"encoding/json"
	"net/mail"
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
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
		if rootLevelName == "" {
			continue
		}

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
			if subModuleName == "" {
				continue
			}

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
		if module.Name == "" || module.PackageDownloadLocation == "" {
			continue
		}

		collection = append(collection, module)
	}

	return collection, nil
}

func convertCargoPackageToModule(dep CargoPackage) models.Module {
	localPath := convertToLocalPath(dep.ManifestPath)
	supplier := getPackageSupplier(dep.Authors, dep.Name)
	donwloadURL := getPackageDownloadLocation(dep)

	module := models.Module{
		Version:    dep.Version,
		Name:       dep.Name,
		Root:       false,
		PackageURL: formatPackageURL(dep),
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(dep.ID),
		},
		LocalPath:               localPath,
		PackageHomePage:         dep.Homepage,
		Supplier:                supplier,
		PackageDownloadLocation: donwloadURL,
		Modules:                 map[string]*models.Module{},
	}

	licensePkg, err := helper.GetLicenses(localPath)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	} else if dep.License != "" {
		module.LicenseDeclared = dep.License
		module.LicenseConcluded = dep.License
	}

	return module
}

func getPackageDownloadLocation(dep CargoPackage) string {
	if dep.Repository != "" {
		return dep.Repository
	}

	source := strings.ReplaceAll(dep.Source, "registry+", "")
	if source != "" {
		return source
	}

	if dep.Homepage != "" {
		return dep.Homepage
	}

	return ""
}

func getPackageSupplier(authors []string, defaultValue string) models.SupplierContact {
	if len(authors) == 0 {
		return models.SupplierContact{
			Name: defaultValue,
		}
	}

	var supplier models.SupplierContact

	mainAuthor := authors[0]
	author, _ := mail.ParseAddress(mainAuthor)

	if author != nil {
		supplier = models.SupplierContact{
			Name:  author.Name,
			Email: author.Address,
			Type:  models.Person,
		}
	}

	if supplier.Email == "" {
		supplier.Type = models.Organization
	}

	if supplier.Name == "" {
		if mainAuthor != "" {
			supplier.Name = mainAuthor
		} else {
			supplier.Name = defaultValue
		}
	}

	return supplier
}

func (m *mod) getRootModule(path string) (models.Module, error) {
	name, err := m.getRootProjectName(path)
	if err != nil {
		return models.Module{}, err
	}

	cargoMetadata, err := m.getCargoMetadata(path)
	if err != nil {
		return models.Module{}, err
	}

	packages := cargoMetadata.Packages
	rootPackage, _ := findPackageByName(packages, name)
	mod := convertCargoPackageToRootModule(rootPackage)
	return mod, nil
}

func convertCargoPackageToRootModule(dep CargoPackage) models.Module {

	localPath := convertToLocalPath(dep.ManifestPath)

	module := models.Module{
		Version:    dep.Version,
		Name:       dep.Name,
		Root:       true,
		PackageURL: formatPackageURL(dep),
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(dep.ID),
		},
		LocalPath:               localPath,
		PackageHomePage:         removeURLProtocol(dep.Homepage),
		Supplier:                getPackageSupplier(dep.Authors, dep.Name),
		Modules:                 map[string]*models.Module{},
		PackageDownloadLocation: dep.Repository,
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

func getDefaultPackageURL(dep CargoPackage) string {
	if dep.Homepage != "" {
		return dep.Homepage
	}

	if dep.Source != "" {
		return dep.Source
	}

	return dep.Repository
}

func formatPackageURL(dep CargoPackage) string {
	URL := getDefaultPackageURL(dep)
	URL = removeURLProtocol(URL)
	URL = removeRegisrySuffix(URL)

	return URL
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

func (m *mod) getRootProjectName(path string) (string, error) {
	err := m.buildCmd(RootModuleNameCmd, path)
	if err != nil {
		return "", err
	}

	pckidRoot, err := m.command.Output()
	if err != nil {
		return "", erroRootPackageInformation
	}
	parts := strings.Split(pckidRoot, "/")
	lastpart := parts[len(parts)-1]
	lastpart = strings.ReplaceAll(lastpart, "\n", "")

	rootNameParts := strings.Split(lastpart, "#")
	name := rootNameParts[0]

	return name, nil
}

func findPackageByName(packages []CargoPackage, name string) (CargoPackage, bool) {

	for _, mod := range packages {
		if mod.Name == name {
			return mod, true
		}
	}

	return CargoPackage{}, false
}
