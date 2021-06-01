package yarn

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"spdx-sbom-generator/internal/licenses"
	"spdx-sbom-generator/internal/reader"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type yarn struct {
	metadata models.PluginMetadata
}

var (
	errDependenciesNotFound = errors.New("please install dependencies by running yarn install")
	yarnRegistry            = "https://registry.yarnpkg.com"
	lockFile = "yarn.lock"
)

// New creates a new yarn instance
func New() *yarn {
	return &yarn{
		metadata: models.PluginMetadata{
			Name:       "Yarn Package Manager",
			Slug:       "yarn",
			Manifest:   []string{"package.json", lockFile},
			ModulePath: []string{"node_modules"},
		},
	}
}

// GetMetadata returns metadata descriptions Name, Slug, Manifest, ModulePath
func (m *yarn) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid checks if module has a valid Manifest file
// for yarn manifest file is package.json
func (m *yarn) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return false
		}
	}
	return true
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *yarn) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if !helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return errDependenciesNotFound
		}
	}

	for i := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return errDependenciesNotFound
		}
	}
	return nil
}

// GetVersion returns yarn version
func (m *yarn) GetVersion() (string, error) {
	cmd := exec.Command("yarn", "-v")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	if len(strings.Split(string(output), ".")) != 3 {
		return "", fmt.Errorf("unexpected version format: %s", output)
	}

	return string(output), nil
}

// SetRootModule ...
func (m *yarn) SetRootModule(path string) error {
	return nil
}


// GetRootModule return
//root package information ex. Name, Version
func (m *yarn) GetRootModule(path string) (*models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return nil, err
	}
	mod := &models.Module{}

	if pkResult["name"] !=nil {
		mod.Name = pkResult["name"].(string)
	}
	if pkResult["author"] != nil {
		mod.Supplier.Name = pkResult["author"].(string)
	}
	if pkResult["version"] != nil {
		mod.Version = pkResult["version"].(string)
	}

	mod.Modules = map[string]*models.Module{}

	return mod, nil
}

// ListUsedModules return brief info of installed modules, Name and Version
func (m *yarn) ListUsedModules(path string) ([]models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return nil, err
	}
	modules := make([]models.Module, 0)
	deps := pkResult["dependencies"].(map[string]interface{})

	for k, v := range deps {
		var mod models.Module
		mod.Name = k
		mod.Version = strings.TrimPrefix(v.(string), "^")
		modules = append(modules, mod)
	}

	return modules, nil
}

// ListModulesWithDeps return all info of installed modules
func (m *yarn) ListModulesWithDeps(path string) ([]models.Module, error) {
	deps, err := helper.ReadLockFile(filepath.Join(path, lockFile))
	if err != nil {
		return nil, err
	}
	lic := licenses.DB

	return m.buildDependencies(path, deps, lic), nil
}

func (m *yarn) buildDependencies(path string, deps []helper.Package, licenses map[string]string) []models.Module {
	modules := make([]models.Module, 0)
	for _,d := range deps {
		var mod models.Module
		mod.Name = d.Name
		mod.Version = d.Version

		// todo: handle mod.supplier

		r := strings.TrimSuffix(strings.TrimPrefix(d.Resolved, "\""), "\"")
		if strings.Contains(r, yarnRegistry) {
		}

		mod.PackageURL = r
		rArr := strings.Split(d.Integrity, "-")
		mod.CheckSum = &models.CheckSum{
			Value:     rArr[1],
			Algorithm: models.HashAlgorithm(rArr[0]),
		}
		licensePath := filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, "LICENSE")
		if helper.Exists(licensePath) {
			mod.Copyright = helper.GetCopyrightText(licensePath)
		}

		mod.LicenseDeclared = helper.GetJSLicense(path, d.PkPath, licenses, m.metadata.ModulePath[0], m.metadata.Manifest[0])

		modules = append(modules, mod)
	}
	return modules
}
