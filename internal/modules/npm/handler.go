package npm

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

type npm struct {
	metadata models.PluginMetadata
}

var (
	errDependenciesNotFound = errors.New("please install dependencies by running npm install")
	shrink                  = "npm-shrinkwrap.json"
	npmRegistry             = "https://registry.npmjs.org"
	lockFile                = "package-lock.json"
)

// New creates a new npm instance
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
	if helper.Exists(filepath.Join(path, m.metadata.Manifest[1])) {
		return true
	}
	return false
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *npm) HasModulesInstalled(path string) error {
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

// GetVersion returns npm version
func (m *npm) GetVersion() (string, error) {
	cmd := exec.Command("npm", "--v")
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

	mod.Modules = map[string]*models.Module{}

	return mod, nil
}

// ListUsedModules return brief info of installed modules, Name and Version
func (m *npm) ListUsedModules(path string) ([]models.Module, error) {
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
func (m *npm) ListModulesWithDeps(path string) ([]models.Module, error) {
	pk := lockFile
	if helper.Exists(filepath.Join(path, shrink)) {
		pk = shrink
	}
	r := reader.New(filepath.Join(path, pk))
	pkResults, err := r.ReadJson()
	if err != nil {
		return nil, err
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

		mod.LicenseDeclared = m.getLicense(path, key, licenses)

		modules = append(modules, mod)
	}
	return modules
}

func (m *npm) getLicense(path string, pkName string, licenses map[string]string) string {
	licenseDeclared := ""
	r := reader.New(filepath.Join(path, m.metadata.ModulePath[0], pkName, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return ""
	}
	pkLic := ""
	if pkResult["licenses"] != nil {
		l := pkResult["licenses"].([]interface{})

		for i := range l {
			if i > 0 {
				pkLic += " OR"
				pkLic += l[i].(map[string]interface{})["type"].(string)
				continue
			}
			pkLic += l[i].(map[string]interface{})["type"].(string)
		}
	}
	if pkResult["license"] != nil {
		pkLic = pkResult["license"].(string)
	}

	if pkLic != "" {
		for k, _ := range licenses {
			if pkLic == k {
				licenseDeclared = pkLic
				break
			}
		}
	}
	if pkLic != "" && licenseDeclared == "" && strings.HasSuffix(pkLic, "or later") {
		licenseDeclared = strings.Replace(pkLic, "or later", "+", 1)
	}
	if pkLic != "" && licenseDeclared == "" {
		licenseDeclared = pkLic
	}
	if pkLic == "" {
		licenseDeclared = "NONE"
	}

	return licenseDeclared

}

type dependency struct {
	version      string
	resolved     string
	integrity    string
	requires     map[string]string
	dev          string
	dependencies []dependency
}
