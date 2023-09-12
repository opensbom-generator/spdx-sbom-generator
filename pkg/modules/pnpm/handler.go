// SPDX-License-Identifier: Apache-2.0

package pnpm

import (
	"crypto/sha256"
	"errors"
	"fmt"
	"gopkg.in/yaml.v3"
	"io/ioutil"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/reader"
)

type pnpm struct {
	metadata models.PluginMetadata
}

var (
	shrink                  = "npm-shrinkwrap.json"
	errDependenciesNotFound = errors.New("unable to generate SPDX file, no modules founded. Please install them before running spdx-sbom-generator, e.g.: `pnpm install`")
	lockFile                = "pnpm-lock.yaml"
	rg                      = regexp.MustCompile(`^(((git|hg|svn|bzr)\+)?(http:\/\/www\.|https:\/\/www\.|http:\/\/|https:\/\/|ssh:\/\/|git:\/\/|svn:\/\/|sftp:\/\/|ftp:\/\/)?[a-z0-9]+([\-\.]{1}[a-z0-9]+){0,100}\.[a-z]{2,5}(:[0-9]{1,5})?(\/.*))|(git\+git@[a-zA-Z0-9\.]+:[a-zA-Z0-9/\\.@]+)|(bzr\+lp:[a-zA-Z0-9\.]+)$`)
)

// New creates a new pnpm instance
func New() *pnpm {
	return &pnpm{
		metadata: models.PluginMetadata{
			Name:       "Performant Node Package Manager",
			Slug:       "pnpm",
			Manifest:   []string{"package.json", lockFile},
			ModulePath: []string{"node_modules"},
		},
	}
}

// GetMetadata returns metadata descriptions Name, Slug, Manifest, ModulePath
func (m *pnpm) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid checks if module has a valid Manifest file
// for pnpm manifest file is package.json
func (m *pnpm) IsValid(path string) bool {
	for _, p := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, p)) {
			return false
		}
	}
	return true
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *pnpm) HasModulesInstalled(path string) error {
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

// GetVersion returns pnpm version
func (m *pnpm) GetVersion() (string, error) {
	cmd := exec.Command("pnpm", "-v")
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
func (m *pnpm) SetRootModule(path string) error {
	return nil
}

// GetRootModule return
// root package information ex. Name, Version
func (m *pnpm) GetRootModule(path string) (*models.Module, error) {
	r := reader.New(filepath.Join(path, m.metadata.Manifest[0]))
	pkResult, err := r.ReadJson()
	if err != nil {
		return &models.Module{}, err
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
		mod.PackageDownloadLocation = mod.PackageURL
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
func (m *pnpm) ListUsedModules(path string) ([]models.Module, error) {
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
func (m *pnpm) ListModulesWithDeps(path string, globalSettingFile string) ([]models.Module, error) {
	deps, err := readLockFile(filepath.Join(path, lockFile))
	if err != nil {
		return nil, err
	}
	allDeps := appendNestedDependencies(deps)
	return m.buildDependencies(path, allDeps)
}

func (m *pnpm) buildDependencies(path string, deps []dependency) ([]models.Module, error) {
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
	modules = append(modules, *de)
	for _, d := range deps {
		var mod models.Module
		mod.Name = d.Name
		mod.Version = extractVersion(d.Version)
		modules[0].Modules[d.Name] = &models.Module{
			Name:     d.Name,
			Version:  mod.Version,
			CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", d.Name, mod.Version))},
		}
		if len(d.Dependencies) != 0 {
			mod.Modules = map[string]*models.Module{}
			for _, depD := range d.Dependencies {
				ar := strings.Split(strings.TrimSpace(depD), " ")
				name := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(ar[0], "\""), "\""), "@")
				if name == "optionalDependencies:" {
					continue
				}

				version := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ar[1]), "\""), "\"")
				if extractVersion(version) == "*" {
					continue
				}
				mod.Modules[name] = &models.Module{
					Name:     name,
					Version:  extractVersion(version),
					CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", name, version))},
				}
			}
		}
		mod.PackageDownloadLocation = strings.TrimSuffix(strings.TrimPrefix(d.Resolved, "\""), "\"")
		mod.Supplier.Name = mod.Name

		mod.PackageURL = getPackageHomepage(filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, m.metadata.Manifest[0]))
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))
		mod.CheckSum = &models.CheckSum{
			Algorithm: "SHA256",
			Value:     h,
		}

		licensePath := filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, "LICENSE")

		libDirName := fmt.Sprintf("%s@%s", strings.ReplaceAll(d.PkPath, "/", "+"), d.Version)
		if d.Belonging != "" {
			libDirName += fmt.Sprintf("%s_%s", libDirName, d.Belonging)
		}
		licensePathInsidePnpm := filepath.Join(
			path,
			m.metadata.ModulePath[0],
			".pnpm",
			libDirName,
			m.metadata.ModulePath[0],
			d.PkPath,
			"LICENSE",
		)

		var validLicensePath string
		if helper.Exists(licensePath) {
			validLicensePath = licensePath
		} else if helper.Exists(licensePathInsidePnpm) {
			validLicensePath = licensePathInsidePnpm
		} else {
			validLicensePath = ""
		}

		r := reader.New(validLicensePath)
		s := r.StringFromFile()
		mod.Copyright = helper.GetCopyright(s)

		modLic, err := helper.GetLicenses(filepath.Join(path, m.metadata.ModulePath[0], d.PkPath))
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
	return modules, nil
}

func readLockFile(path string) ([]dependency, error) {
	fileContent, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}

	var lockData map[string]interface{}
	err = yaml.Unmarshal(fileContent, &lockData)
	if err != nil {
		return nil, err
	}

	packages, ok := lockData["packages"].(map[string]interface{})
	if !ok {
		return nil, fmt.Errorf("invalid lock file format")
	}

	dependencies := make([]dependency, 0)

	for pkgName, pkg := range packages {
		pkgMap, ok := pkg.(map[string]interface{})
		if !ok {
			continue
		}

		dep := dependency{}

		name, version, belonging := splitPackageNameAndVersion(pkgName)
		nameWithoutAt, pkPath, nameAndVersion := processName(name)
		dep.Name = fmt.Sprintf("%s", nameWithoutAt)
		dep.PkPath = fmt.Sprintf("%s", pkPath)
		dep.Version = version
		dep.Belonging = belonging
		if resolution, ok := pkgMap["resolution"].(map[string]interface{}); ok {
			if tarball, ok := resolution["tarball"].(string); ok {
				dep.Resolved = tarball
			}
			if integrity, ok := resolution["integrity"].(string); ok {
				dep.Integrity = integrity
			}
		}
		if dep.Resolved == "" {
			// .npmrc
			registry := "https://registry.npmjs.org"
			dep.Resolved = fmt.Sprintf("%s/%s/-/%s-%s.tgz", registry, name, nameAndVersion, dep.Version)
		}

		dependenciesRaw, ok := pkgMap["dependencies"].(map[string]interface{})
		if ok {
			for depName, ver := range dependenciesRaw {
				depPath := fmt.Sprintf("%s %s", depName, ver)
				dep.Dependencies = append(dep.Dependencies, strings.TrimSpace(depPath))
			}
		}

		dependencies = append(dependencies, dep)
	}

	return dependencies, nil
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

func extractVersion(s string) string {
	t := strings.TrimPrefix(s, "^")
	t = strings.TrimPrefix(t, "~")
	t = strings.TrimPrefix(t, ">")
	t = strings.TrimPrefix(t, "=")

	t = strings.Split(t, " ")[0]
	return t
}

func splitPackageNameAndVersion(pkg string) (string, string, string) {
	// Remove parentheses and content inside
	parts := strings.Split(pkg, "(")
	pkg = parts[0]

	atIndex := strings.LastIndex(pkg, "@")
	if atIndex == -1 {
		return "", "", ""
	}

	name := strings.TrimLeft(pkg[:atIndex], "/")
	version := pkg[atIndex+1:]

	// Extract extra content in parentheses
	extra := ""
	if len(parts) > 1 {
		extra = strings.TrimSuffix(parts[1], ")")
	}

	return name, version, extra
}

func processName(name string) (string, string, string) {
	nameWithoutAt := strings.TrimPrefix(name, "@")
	pkPath := name
	pkgNameParts := strings.Split(nameWithoutAt, "/")
	version := pkgNameParts[len(pkgNameParts)-1]

	return nameWithoutAt, pkPath, version
}

func appendNestedDependencies(deps []dependency) []dependency {
	allDeps := make([]dependency, 0)
	for _, d := range deps {
		allDeps = append(allDeps, d)
		if len(d.Dependencies) > 0 {
			for _, depD := range d.Dependencies {
				ar := strings.Split(strings.TrimSpace(depD), " ")
				name := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(ar[0], "\""), "\""), "@")
				if name == "optionalDependencies:" {
					continue
				}

				version := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(ar[1]), "\""), "\"")
				if extractVersion(version) == "*" {
					continue
				}
				allDeps = append(allDeps, dependency{Name: name, Version: extractVersion(version)})
			}
		}
	}
	return allDeps
}
