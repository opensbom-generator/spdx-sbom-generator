package composer

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

// rest of the file below
type composer struct {
	metadata models.PluginMetadata
}

var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `go mod vendor` or `go get` might solve the issue.")

// New ...
func New() *composer {
	return &composer{
		metadata: models.PluginMetadata{
			Name:       "composer Package Manager",
			Slug:       "composer",
			Manifest:   []string{"composer.json"},
			ModulePath: []string{"vendor"},
		},
	}
}

// GetMetadata ...
func (m *composer) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *composer) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *composer) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.FileExists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion ...
func (m *composer) GetVersion() (string, error) {
	cmd := exec.Command("composer", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))

	if fields[0] != "Composer" || fields[1] != "version" {
		return "", fmt.Errorf("unexpected output format: %s", output)
	}

	return fields[2], nil
}

// GetModule ...
func (m *composer) GetModule(path string) ([]models.Module, error) {
	return nil, nil
}

// ListAllModules ...
func (m *composer) ListAllModules(path string) ([]models.Module, error) {
	return nil, nil
}

// ListModules ...
func (m *composer) ListModules(path string) ([]models.Module, error) {

	var modules []models.Module
	var err error

	composerInfo, err := ListModulesFromLock()
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	modules, err = parseLockModules(composerInfo)

	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	return modules, nil
}

func ListModulesFromLock() (ComposerInfo, error) {

	raw, err := ioutil.ReadFile("composer.lock")
	if err != nil {
		return ComposerInfo{}, err
	}

	var lock ComposerInfo
	err = json.Unmarshal(raw, &lock)

	return lock, nil
}

func parseLockModules(info ComposerInfo) ([]models.Module, error) {

	modules := make([]models.Module, 0)

	for _, dep := range info.Packages {
		mod := getModuleFromComposerPackage(dep)
		modules = append(modules, mod)
	}

	for _, dep := range info.PackagesDev {
		mod := getModuleFromComposerPackage(dep)
		modules = append(modules, mod)
	}

	return modules, nil
}

func getModuleFromComposerPackage(dep ComposerInfoPackage) models.Module {
	var mod models.Module
	mod.Name = getName(dep.Name)
	mod.PackageURL = genUrl(dep)
	mod.Version = dep.Version
	mod.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     dep.Dist.Shasum,
	}
	mod.LicenseDeclared = getLicenseDeclared(dep)
	mod.OtherLicense = getOtherLicense(dep)

	return mod
}

func getOtherLicense(module ComposerInfoPackage) []*models.License {

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

func getLicenseDeclared(module ComposerInfoPackage) string {
	licenses := module.License

	if len(licenses) > 0 {
		return ""
	}

	return licenses[0]
}

func getName(moduleName string) string {
	s := strings.Split(moduleName, "/")
	return s[1]
}

func genUrl(dep ComposerInfoPackage) string {
	return "pkg:composer/" + dep.Name + "@" + dep.Version
}

type ComposerInfo struct {
	Packages    []ComposerInfoPackage
	PackagesDev []ComposerInfoPackage `json:"packages-dev"`
}

type ComposerInfoPackageDist struct {
	Type      string
	URL       string
	Reference string
	Shasum    string
}

type ComposerInfoPackage struct {
	Name        string
	Version     string
	Type        string // library
	Authors     []string
	Dist        ComposerInfoPackageDist
	License     []string
	Description string
}
