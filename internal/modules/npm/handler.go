package npm

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
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
	licences                = "licenses.json"
)

// New creates a new npm instance
func New() *npm {
	return &npm{
		metadata: models.PluginMetadata{
			Name:       "Node Package Manager",
			Slug:       "npm",
			Manifest:   []string{"package.json"},
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
		if helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *npm) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.FileExists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
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

// GetModule return root package information ex. Name, Version
func (m *npm) GetModule(path string) ([]models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return nil, err
	}
	modules := make([]models.Module, 0)
	var mod models.Module

	mod.Name = pkResult["name"].(string)
	mod.Modules = map[string]*models.Module{}

	modules = append(modules, mod)

	return modules, nil
}

// ListModules return brief info of installed modules, Name and Version
func (m *npm) ListModules(path string) ([]models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return nil, err
	}
	modules := make([]models.Module, 0)
	deps := pkResult["dependencies"].(map[string]string)

	for k, v := range deps {
		var mod models.Module
		mod.Name = k
		mod.Version = v
	}

	return modules, nil
}

// ListAllModules return all info of installed modules
func (m *npm) ListAllModules(path string) ([]models.Module, error) {
	pk := "package-lock.json"
	if helper.FileExists(filepath.Join(path, shrink)) {
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

	re := reader.New(licences)
	lic, err := re.ReadJson()
	lics := lic["licenses"].([]interface{})
	licenses := make(map[string]string)
	for i := range lics {
		licenses[lics[i].(map[string]interface{})["licenseId"].(string)] = lics[i].(map[string]interface{})["name"].(string)
	}

	return m.buildDependencies(path, deps, licenses), nil
}

func (m *npm) buildDependencies(path string, deps map[string]interface{}, licenses map[string]string) []models.Module {
	modules := make([]models.Module, 0)
	fmt.Println("ddddd", len(deps))
	for key, dd := range deps {
		d := dd.(map[string]interface{})
		var mod models.Module
		mod.Name = fmt.Sprintf("%s-%s", key, d["version"].(string))
		mod.Version = d["version"].(string)

		// todo: handle mod.supplier
		// todo: handle relationships

		resolved := d["resolved"].(string)
		if strings.Contains(resolved, npmRegistry) {
		}

		mod.PackageURL = d["resolved"].(string)
		/*		sha, err := hash.SHA256ForFile(mod.Name)
				if err != nil {
					continue
				}
				mod.CheckSum = &models.CheckSum{
					Value:     sha,
					Algorithm: "SHA256",
				}*/
		licensePath := filepath.Join(path, m.metadata.ModulePath[0], key, "LICENSE")
		if helper.FileExists(licensePath) {
			r := reader.New(licensePath)
			mod.Copyright = r.GetCopyrightText()
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
	pkLic := pkResult["license"].(string)

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
