package composer

import (
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"io/ioutil"
	"strings"

	"spdx-sbom-generator/internal/models"
)

type ComposerLockFile struct {
	Packages    []ComposerLockPackage
	PackagesDev []ComposerLockPackage `json:"packages-dev"`
}

type ComposerLockPackage struct {
	Name        string
	Version     string
	Type        string
	Dist        ComposerLockPackageDist
	License     []string
	Description string
	Source      ComposerLockPackageSource
}
type ComposerLockPackageSource struct {
	Type      string
	URL       string
	Reference string
}

type ComposerLockPackageDist struct {
	Type      string
	URL       string
	Reference string
	Shasum    string
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

func getModulesFromComposerLockFile() ([]models.Module, error) {

	modules := make([]models.Module, 0)

	info, err := getComposerLockFileData()
	if err != nil {
		return nil, err
	}

	mainMod, err := getProjectInfo()
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

	var mod models.Module
	mod.Name = getName(dep.Name)
	mod.PackageURL = genUrlFromComposerPackage(dep)
	mod.Version = normalizePackageVersion(dep.Version)
	mod.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     getCheckSumValue(dep),
	}
	mod.LicenseDeclared = getLicenseDeclared(dep)
	mod.OtherLicense = getOtherLicense(dep)
	mod.Modules = map[string]*models.Module{}

	return mod
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

func getOtherLicense(module ComposerLockPackage) []*models.License {

	licenses := module.License

	var collection []*models.License

	if len(licenses) > 0 {
		return collection
	}

	for _, lib := range licenses {
		collection = append(collection, &models.License{
			Name: lib,
		})
	}

	return collection
}

func getLicenseDeclared(module ComposerLockPackage) string {
	licenses := module.License

	if len(licenses) > 0 {
		return ""
	}

	return licenses[0]
}
