// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/reader"
)

type npm struct {
	metadata models.PluginMetadata
}

var (
	shrink      = "npm-shrinkwrap.json"
	npmRegistry = "https://registry.npmjs.org"
	lockFile    = "package-lock.json"
)

// New creates a new npm manager instance
func New() *npm {
	return &npm{
		metadata: models.PluginMetadata{
			Name:       "Node Package Manager",
			Slug:       "npm",
			Manifest:   []string{"package.json", lockFile},
			ModulePath: []string{"node_modules"},
		},
	}
}

// GetMetadata returns metadata descriptions Name, Slug, Manifest, ModulePath
func (m *npm) GetMetadata() models.PluginMetadata {
	return m.metadata
}

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
	if err != nil {
		return "", err
	}

	if len(strings.Split(string(output), ".")) != 3 {
		return "", errNoNpmCommand
	}

	return string(output), nil
}

// SetRootModule ...
func (m *npm) SetRootModule(path string) error {
	return nil
}

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
	if pkResult["homepage"] != nil {
		fmt.Println("x1: ", pkResult["homepage"].(string))
		mod.PackageURL = helper.RemoveURLProtocol(pkResult["homepage"].(string))
		fmt.Println("x2: ", mod.PackageURL)
	}
	mod.Modules = map[string]*models.Module{}

	mod.Copyright = getCopyright(path)
	modLic, err := helper.GetLicenses(path)
	if err != nil {
		return mod, nil
	}
	mod.LicenseDeclared = helper.BuildLicenseDeclared(modLic.ID)
	mod.LicenseConcluded = helper.BuildLicenseConcluded(modLic.ID)
	mod.CommentsLicense = modLic.Comments
	if !helper.LicenseSPDXExists(modLic.ID) {
		mod.OtherLicense = append(mod.OtherLicense, modLic)
	}

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

	return m.buildDependencies(path, deps)
}

func (m *npm) buildDependencies(path string, deps map[string]interface{}) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	de, err := m.GetRootModule(path)
	if err != nil {
		return modules, err
	}
	h := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s-%s", de.Name, de.Version))))
	de.CheckSum = &models.CheckSum{
		Algorithm: "SHA256",
		Value: h,
	}
	modules = append(modules, *de)
	for key, dd := range deps {
		d := dd.(map[string]interface{})
		var mod models.Module
		mod.Version = d["version"].(string)
		mod.Name = strings.TrimPrefix(key, "@")

		r := ""
		if d["resolved"] != nil {
			r = d["resolved"].(string)
			if strings.Contains(r, npmRegistry) {
				mod.Supplier.Name = "NOASSERTION"
			}
		}
		mod.PackageURL = helper.RemoveURLProtocol(r)
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))
		mod.CheckSum = &models.CheckSum{
			Algorithm: "SHA256",
			Value: h,
		}
		mod.Copyright = getCopyright(filepath.Join(path, m.metadata.ModulePath[0], key))
		modLic, err := helper.GetLicenses(filepath.Join(path, m.metadata.ModulePath[0], key))
		if err != nil {
			continue
		}
		mod.LicenseDeclared = helper.BuildLicenseDeclared(modLic.ID)
		mod.LicenseConcluded = helper.BuildLicenseConcluded(modLic.ID)
		mod.CommentsLicense = modLic.Comments
		if !helper.LicenseSPDXExists(modLic.ID) {
			mod.OtherLicense = append(mod.OtherLicense, modLic)
		}
		mod.Modules = map[string]*models.Module{}
		if d["requires"] != nil {
			modDeps := d["requires"].(map[string]interface{})
			for k, v := range modDeps {
				name := strings.TrimPrefix(k, "@")
				version := strings.TrimPrefix(v.(string), "^")
				mod.Modules[k] = &models.Module{
					Name:     fmt.Sprintf("%s-%s", name, version),
					Version:  version,
					CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", name, version))},
				}

			}
		}

		modules = append(modules, mod)
	}
	return modules, nil
}

func getCopyright(path string) string {
	licensePath := filepath.Join(path, "LICENSE")
	if helper.Exists(licensePath) {
		r := reader.New(licensePath)
		s := r.StringFromFile()
		return helper.GetCopyright(s)
	}

	licenseMDPath, err := filepath.Glob(filepath.Join(path, "LICENSE*"))
	if err != nil {
		return ""
	}
	if len(licenseMDPath) > 0 && helper.Exists(licenseMDPath[0]) {
		r := reader.New(licenseMDPath[0])
		s := r.StringFromFile()
		return helper.GetCopyright(s)
	}

	return ""
}
