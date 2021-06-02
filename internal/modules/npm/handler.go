<<<<<<< HEAD
package npm

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/licenses"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/reader"
=======
// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"os/exec"
	"path/filepath"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
)

type npm struct {
	metadata models.PluginMetadata
}

<<<<<<< HEAD
var (
	errDependenciesNotFound = errors.New("please install dependencies by running npm install")
	shrink                  = "npm-shrinkwrap.json"
	npmRegistry             = "https://registry.npmjs.org"
	lockFile                = "package-lock.json"
)

// New creates a new npm manager instance
=======
// New ...
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
func New() *npm {
	return &npm{
		metadata: models.PluginMetadata{
			Name:       "Node Package Manager",
			Slug:       "npm",
<<<<<<< HEAD
			Manifest:   []string{"package.json", lockFile},
=======
			Manifest:   []string{"package.json"},
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
			ModulePath: []string{"node_modules"},
		},
	}
}

<<<<<<< HEAD
// GetMetadata returns metadata descriptions Name, Slug, Manifest, ModulePath
=======
// GetMetadata ...
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
func (m *npm) GetMetadata() models.PluginMetadata {
	return m.metadata
}

<<<<<<< HEAD
// IsValid checks if module has a valid Manifest file
// for npm manifest file is package.json
func (m *npm) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return false
		}
	}
	return true
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *npm) HasModulesInstalled(path string) error {
	for _, p := range m.metadata.ModulePath {
		if !helper.Exists(filepath.Join(path, p)) {
			return errDependenciesNotFound
		}
	}

	for _, p := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, p)) {
			return errDependenciesNotFound
		}
	}
	return nil
}

// GetVersion returns npm version
func (m *npm) GetVersion() (string, error) {
	cmd := exec.Command("npm", "--v")
	output, err := cmd.Output()
=======
// IsValid ...
func (m *npm) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *npm) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion ...
func (m *npm) GetVersion() (string, error) {
	output, err := exec.Command("npm", "--version").Output()
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
	if err != nil {
		return "", err
	}

<<<<<<< HEAD
	if len(strings.Split(string(output), ".")) != 3 {
		return "", fmt.Errorf("unexpected version format: %s", output)
	}

=======
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
	return string(output), nil
}

// SetRootModule ...
func (m *npm) SetRootModule(path string) error {
	return nil
}

<<<<<<< HEAD
// GetRootModule return root package information ex. Name, Version
func (m *npm) GetRootModule(path string) (*models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return nil, err
	}
	mod := &models.Module{}

	if pkResult["name"] != nil {
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
func (m *npm) ListUsedModules(path string) ([]models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return []models.Module{}, err
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
func (m *npm) ListModulesWithDeps(path string) ([]models.Module, error) {
	pk := lockFile
	if helper.Exists(filepath.Join(path, shrink)) {
		pk = shrink
	}

	r := reader.New(filepath.Join(path, pk))
	pkResults, err := r.ReadJson()
	if err != nil {
		return []models.Module{}, err
	}

	deps, ok := pkResults["packages"].(map[string]interface{})
	if !ok {
		deps = pkResults["dependencies"].(map[string]interface{})
	}
	lic := licenses.DB

	return m.buildDependencies(path, deps, lic), nil
}

func (m *npm) buildDependencies(path string, deps map[string]interface{}, licenses map[string]string) []models.Module {
	modules := make([]models.Module, 0)
	for key, dd := range deps {
		d := dd.(map[string]interface{})
		var mod models.Module
		mod.Name = fmt.Sprintf("%s-%s", key, d["version"].(string))
		mod.Version = d["version"].(string)

		// todo: handle mod.supplier

		r := d["resolved"].(string)
		if strings.Contains(r, npmRegistry) {
		}

		mod.PackageURL = r
		rArr := strings.Split(d["integrity"].(string), "-")
		mod.CheckSum = &models.CheckSum{
			Value:     rArr[1],
			Algorithm: models.HashAlgorithm(rArr[0]),
		}
		licensePath := filepath.Join(path, m.metadata.ModulePath[0], key, "LICENSE")
		if helper.Exists(licensePath) {
			mod.Copyright = helper.GetCopyrightText(licensePath)
		}

		mod.LicenseDeclared = helper.GetJSLicense(path, key, licenses, m.metadata.ModulePath[0], m.metadata.Manifest[0])

		modules = append(modules, mod)
	}
	return modules
=======
// GetRootModule ...
func (m *npm) GetRootModule(path string) (*models.Module, error) {
	return nil, nil
}

// ListUsedModules...
func (m *npm) ListUsedModules(path string) ([]models.Module, error) {
	return nil, nil
}

// ListModulesWithDeps ...
func (m *npm) ListModulesWithDeps(path string) ([]models.Module, error) {
	return nil, nil
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
}
