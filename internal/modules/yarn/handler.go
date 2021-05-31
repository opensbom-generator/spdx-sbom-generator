package yarn

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

type yarn struct {
	metadata models.PluginMetadata
}

var (
	errDependenciesNotFound = errors.New("please install dependencies by running yarn install")
	yarnRegistry            = "https://registry.yarnpkg.com"
	licences                = "licenses.json"
)

// New creates a new yarn instance
func New() *yarn {
	return &yarn{
		metadata: models.PluginMetadata{
			Name:       "Yarn Package Manager",
			Slug:       "yarn",
			Manifest:   []string{"package.json", "yarn.lock"},
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
		if helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *yarn) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if !helper.FileExists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return errDependenciesNotFound
		}
	}

	for i := range m.metadata.Manifest {
		if !helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
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

// GetModule return
//root package information ex. Name, Version
func (m *yarn) GetModule(path string) ([]models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return nil, err
	}
	modules := make([]models.Module, 0)
	var mod models.Module

	mod.Name = pkResult["name"].(string)
	mod.Supplier.Name = pkResult["author"].(string)
	mod.Version = pkResult["version"].(string)

	mod.Modules = map[string]*models.Module{}
	modules = append(modules, mod)

	return modules, nil
}

// ListModules return brief info of installed modules, Name and Version
func (m *yarn) ListModules(path string) ([]models.Module, error) {
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
func (m *yarn) ListAllModules(path string) ([]models.Module, error) {
	pk := "yarn.lock"
	deps, err := helper.ReadLockFile(pk)
	if err != nil {
		return nil, err
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

func (m *yarn) buildDependencies(path string, deps []helper.Package, licenses map[string]string) []models.Module {
	modules := make([]models.Module, 0)
	for _,d := range deps {
		var mod models.Module
		mod.Name = d.Name
		mod.Version = d.Version

		// todo: handle mod.supplier

		r := d.Resolved
		if strings.Contains(r, yarnRegistry) {
		}

		mod.PackageURL = r
		rArr := strings.Split(d.Integrity, "-")
		mod.CheckSum = &models.CheckSum{
			Value:     rArr[1],
			Algorithm: models.HashAlgorithm(rArr[0]),
		}
		licensePath := filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, "LICENSE")
		if helper.FileExists(licensePath) {
			mod.Copyright = helper.GetCopyrightText(licensePath)
		}

		mod.LicenseDeclared = m.getLicense(path, d.PkPath, licenses)

		modules = append(modules, mod)
	}
	return modules
}

func (m *yarn) getLicense(path string, pkName string, licenses map[string]string) string {
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
