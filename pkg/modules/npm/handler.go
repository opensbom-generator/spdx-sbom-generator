// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/reader"
)

type npm struct {
	metadata models.PluginMetadata
}

var (
	shrink      = "npm-shrinkwrap.json"
	npmRegistry = "https://registry.npmjs.org"
	lockFile    = "package-lock.json"
	rg          = regexp.MustCompile(`^(((git|hg|svn|bzr)\+)?(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|ssh:\/\/|git:\/\/|svn:\/\/|sftp:\/\/|ftp:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+){0,100}\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*))|(git\+git@[a-zA-Z0-9\.]+:[a-zA-Z0-9/\\.@]+)|(bzr\+lp:[a-zA-Z0-9\.]+)$`)
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

	splitedPath := strings.Split(path, "/")
	mod.Name = splitedPath[len(splitedPath)-1]
	if pkResult["name"] != nil {
		mod.Name = pkResult["name"].(string)
	}
	if pkResult["author"] != nil {
		mod.Supplier.Name = pkResult["author"].(string)
	}
	if pkResult["version"] != nil {
		mod.Version = pkResult["version"].(string)
	}
	repository := pkResult["repository"]
	if repository != nil {
		if rep, ok := repository.(string); ok {
			mod.PackageDownloadLocation = rep
		}
		if _, ok := repository.(map[string]interface{}); ok && repository.(map[string]interface{})["url"] != nil {
			mod.PackageDownloadLocation = repository.(map[string]interface{})["url"].(string)
		}
	}
	if pkResult["homepage"] != nil {
		mod.PackageURL = helper.RemoveURLProtocol(pkResult["homepage"].(string))
	}
	if !rg.MatchString(mod.PackageDownloadLocation) {
		mod.PackageDownloadLocation = "NONE"
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
func (m *npm) ListModulesWithDeps(path string, globalSettingFile string) ([]models.Module, error) {
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
		Value:     h,
	}
	de.Supplier.Name = de.Name
	if de.PackageDownloadLocation == "" {
		de.PackageDownloadLocation = de.Name
	}
	rootDeps := getPackageDependencies(deps, "dependencies")
	for k, v := range rootDeps {
		de.Modules[k] = v
	}
	modules = append(modules, *de)

	allDeps := appendNestedDependencies(deps)
	for key, dd := range allDeps {
		depName := strings.TrimPrefix(key, "@")
		for nkey := range dd {
			var mod models.Module
			d := dd[nkey].(map[string]interface{})
			mod.Version = strings.TrimSpace(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimPrefix(nkey, "^"), "~"), ">"), "="))
			mod.Version = strings.Split(mod.Version, " ")[0]
			mod.Name = depName

			r := ""
			if d["resolved"] != nil {
				r = d["resolved"].(string)
				mod.PackageDownloadLocation = r
			}
			if mod.PackageDownloadLocation == "" {
				r := "https://www.npmjs.com/package/%s/v/%s"
				mod.PackageDownloadLocation = fmt.Sprintf(r, mod.Name, mod.Version)
			}
			mod.Supplier.Name = mod.Name

			mod.PackageURL = getPackageHomepage(filepath.Join(path, m.metadata.ModulePath[0], key, m.metadata.Manifest[0]))
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))
			mod.CheckSum = &models.CheckSum{
				Algorithm: "SHA256",
				Value:     h,
			}

			mod.Copyright = getCopyright(filepath.Join(path, m.metadata.ModulePath[0], key))
			mod.Modules = map[string]*models.Module{}
			if dd["requires"] != nil {
				modDeps := dd["requires"].(map[string]interface{})
				deps := getPackageDependencies(modDeps, "requires")
				for k, v := range deps {
					mod.Modules[k] = v
				}
			}

			if dd["dependencies"] != nil {
				modDeps := dd["dependencies"].(map[string]interface{})
				deps := getPackageDependencies(modDeps, "dependencies")
				for k, v := range deps {
					mod.Modules[k] = v
				}
			}

			modLic, err := helper.GetLicenses(filepath.Join(path, m.metadata.ModulePath[0], key))
			if err != nil {
				modules = append(modules, mod)
				continue
			}
			mod.LicenseDeclared = helper.BuildLicenseDeclared(modLic.ID)
			mod.LicenseConcluded = helper.BuildLicenseConcluded(modLic.ID)
			mod.CommentsLicense = modLic.Comments
			if !helper.LicenseSPDXExists(modLic.ID) {
				mod.OtherLicense = append(mod.OtherLicense, modLic)
			}

			modules = append(modules, mod)

		}

	}

	return modules, nil
}

func getCopyright(path string) string {
	licensePath := getLicenseFile(path)
	if helper.Exists(licensePath) {
		r := reader.New(licensePath)
		s := r.StringFromFile()
		return helper.GetCopyright(s)
	}

	return ""
}

func getLicenseFile(path string) string {
	licensePath := filepath.Join(path, "LICENSE")
	if helper.Exists(licensePath) {
		return licensePath
	}

	licenseMDPath, err := filepath.Glob(filepath.Join(path, "LICENSE*"))
	if err != nil {
		return ""
	}
	if len(licenseMDPath) > 0 && helper.Exists(licenseMDPath[0]) {
		return licenseMDPath[0]
	}

	licenseMDCaseSensitivePath, err := filepath.Glob(filepath.Join(path, "license*"))
	if err != nil {
		return ""
	}
	if len(licenseMDCaseSensitivePath) > 0 && helper.Exists(licenseMDCaseSensitivePath[0]) {
		return licenseMDCaseSensitivePath[0]
	}
	return ""
}

func getPackageDependencies(modDeps map[string]interface{}, t string) map[string]*models.Module {
	m := make(map[string]*models.Module)
	for k, v := range modDeps {
		name := strings.TrimPrefix(k, "@")
		version := ""
		if t == "dependencies" {
			version = strings.TrimPrefix(v.(map[string]interface{})["version"].(string), "^")
		}
		if t == "requires" {
			version = strings.TrimPrefix(v.(string), "^")
		}
		m[k] = &models.Module{
			Name:     name,
			Version:  version,
			CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", name, version))},
		}
	}
	return m
}

func getPackageHomepage(path string) string {
	r := reader.New(path)
	pkResult, err := r.ReadJson()
	if err != nil {
		return ""
	}
	if pkResult["homepage"] != nil {
		return helper.RemoveURLProtocol(pkResult["homepage"].(string))
	}
	return ""
}

func appendNestedDependencies(deps map[string]interface{}) map[string]map[string]interface{} {
	allDeps := make(map[string]map[string]interface{})
	for k, v := range deps {
		mainDeps := make(map[string]interface{})

		if allDeps[k] != nil {
			mainDeps = allDeps[k]
		}
		mainDeps[v.(map[string]interface{})["version"].(string)] = v
		allDeps[k] = mainDeps

		if r, ok := v.(map[string]interface{})["requires"]; ok {
			appendRequired(r, allDeps)
		}

		if d, ok := v.(map[string]interface{})["dependencies"]; ok {
			appendDependencies(d, allDeps)
		}

	}
	return allDeps
}

func appendDependencies(d interface{}, allDeps map[string]map[string]interface{}) {
	for dk, dv := range d.(map[string]interface{}) {
		m := allDeps[dk]
		if m == nil {
			m = make(map[string]interface{})
		}
		m[dv.(map[string]interface{})["version"].(string)] = dv.(map[string]interface{})
		allDeps[dk] = m
	}
}

func appendRequired(r interface{}, allDeps map[string]map[string]interface{}) {
	for rk, rv := range r.(map[string]interface{}) {
		if rv.(string) == "*" {
			continue
		}
		nestedDeps := allDeps[rk]
		if nestedDeps == nil {
			nestedDeps = make(map[string]interface{})
		}
		nestedDeps[rv.(string)] = map[string]interface{}{"version": rv}
		allDeps[rk] = nestedDeps
	}
}
