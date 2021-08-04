// SPDX-License-Identifier: Apache-2.0

package yarn

import (
	"bufio"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/reader"
)

type yarn struct {
	metadata models.PluginMetadata
}

var (
	errDependenciesNotFound = errors.New("unable to generate SPDX file, no modules founded. Please install them before running spdx-sbom-generator, e.g.: `yarn install`")
	yarnRegistry            = "https://registry.yarnpkg.com"
	lockFile                = "yarn.lock"
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
	for _, p := range m.metadata.Manifest {
		if !helper.Exists(filepath.Join(path, p)) {
			return false
		}
	}
	return true
}

// HasModulesInstalled checks if modules of manifest file already installed
func (m *yarn) HasModulesInstalled(path string) error {
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
	if pkResult["homepage"] != nil {
		mod.PackageURL = helper.RemoveURLProtocol(pkResult["homepage"].(string))
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
func (m *yarn) ListUsedModules(path string) ([]models.Module, error) {
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
func (m *yarn) ListModulesWithDeps(path string) ([]models.Module, error) {
	deps, err := readLockFile(filepath.Join(path, lockFile))
	if err != nil {
		return nil, err
	}

	return m.buildDependencies(path, deps)
}

func (m *yarn) buildDependencies(path string, deps []dependency) ([]models.Module, error) {
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
	modules = append(modules, *de)
	for _, d := range deps {
		var mod models.Module
		mod.Name = d.Name
		mod.Version = d.Version
		modules[0].Modules[d.Name] = &models.Module{
			Name:     d.Name,
			Version:  d.Version,
			CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", d.Name, d.Version))},
		}
		if len(d.Dependencies) != 0 {
			mod.Modules = map[string]*models.Module{}
			for _, depD := range d.Dependencies {
				ar := strings.Split(strings.TrimSpace(depD), " ")
				name := strings.TrimPrefix(strings.TrimSuffix(strings.TrimPrefix(ar[0], "\""), "\""), "@")
				if name == "optionalDependencies:" {
					continue
				}
				version := strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(strings.TrimSpace(ar[1]), "\""), "^"), "\"")
				mod.Modules[name] = &models.Module{
					Name:     name,
					Version:  version,
					CheckSum: &models.CheckSum{Content: []byte(fmt.Sprintf("%s-%s", name, version))},
				}
			}
		}
		r := strings.TrimSuffix(strings.TrimPrefix(d.Resolved, "\""), "\"")
		if strings.Index(r, "#") > 0 {
			r = r[:strings.Index(r, "#")]
		}
		if strings.Contains(r, yarnRegistry) {
			mod.Supplier.Name = "NOASSERTION"
		}

		mod.PackageURL = helper.RemoveURLProtocol(r)
		h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))
		mod.CheckSum = &models.CheckSum{
			Algorithm: "SHA256",
			Value:     h,
		}
		licensePath := filepath.Join(path, m.metadata.ModulePath[0], d.PkPath, "LICENSE")
		if helper.Exists(licensePath) {
			r := reader.New(licensePath)
			s := r.StringFromFile()
			mod.Copyright = helper.GetCopyright(s)
		}

		modLic, err := helper.GetLicenses(filepath.Join(path, m.metadata.ModulePath[0], d.PkPath))
		if err != nil {
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
	file, err := os.Open(path)
	if err != nil {
		return []dependency{}, err
	}
	defer file.Close()
	p := make([]dependency, 0)
	i := -1
	scanner := bufio.NewScanner(file)

	isPk := false
	isDep := false
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		if strings.TrimSpace(text) == "" {
			isPk = false
			isDep = false
			continue
		}
		if isDep {
			p[i].Dependencies = append(p[i].Dependencies, text)
			continue
		}
		if isPk {
			if strings.HasPrefix(text, "  version ") {
				p[i].Version = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(text, "  version "), "\""), "\"")
				n := p[i].Name[:strings.Index(p[i].Name, "@")]
				p[i].Name = n
				p[i].PkPath = p[i].PkPath[:strings.LastIndex(p[i].PkPath, "@")]
				continue
			}
			if strings.HasPrefix(text, "  resolved ") {
				p[i].Resolved = strings.TrimPrefix(text, "  resolved ")
				continue
			}
			if strings.HasPrefix(text, "  integrity ") {
				p[i].Integrity = strings.TrimPrefix(text, "  integrity ")
				continue
			}
			if strings.HasPrefix(text, "  dependencies:") {
				isDep = true
				continue
			}
		}

		if !strings.HasPrefix(scanner.Text(), "  ") {
			isPk = true
			i++
			var dep dependency
			name := text
			name = strings.TrimSpace(name)
			if strings.Contains(name, ",") {
				s := strings.Split(name, ",")
				name = s[0]
			}
			name = strings.TrimPrefix(name, "\"")
			name = strings.TrimSuffix(name, ":")

			dep.PkPath = strings.TrimSuffix(name, "\"")
			name = strings.TrimPrefix(name, "@")

			dep.Name = name
			p = append(p, dep)
			continue
		}
	}

	if err := scanner.Err(); err != nil {
		return []dependency{}, err
	}

	return p, nil
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
