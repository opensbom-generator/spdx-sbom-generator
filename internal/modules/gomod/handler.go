// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"bufio"
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type mod struct {
	metadata models.PluginMetadata
}

var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `go mod vendor` or `go get` might solve the issue.")

// New ...
func New() *mod {
	return &mod{
		metadata: models.PluginMetadata{
			Name:       "Go Modules",
			Slug:       "go-mod",
			Manifest:   []string{"go.mod"},
			ModulePath: []string{"vendor"}, // todo Add other module source
		},
	}
}

// GetMetadata ...
func (m *mod) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *mod) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *mod) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.FileExists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion...
func (m *mod) GetVersion() (string, error) {
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))
	if len(fields) != 4 {
		return "", fmt.Errorf("expected four fields in output, but got %d: %s", len(fields), output)
	}

	if fields[0] != "go" || fields[1] != "version" {
		return "", fmt.Errorf("unexpected output format: %s", output)
	}

	return fields[2], nil
}

// GetModule...
func (m *mod) GetModule(path string) ([]models.Module, error) {
	buf := new(bytes.Buffer)
	if err := helper.ExecCMD(path, buf, "go", "list", "-mod", "readonly", "-json", "-m"); err != nil {
		return nil, fmt.Errorf("listing modules failed: %w", err)
	}
	defer buf.Reset()

	return parseModules(buf)
}

// ListModules...
func (m *mod) ListModules(path string) ([]models.Module, error) {
	buf := new(bytes.Buffer)
	if err := helper.ExecCMD(path, buf, "go", "list", "-mod", "readonly", "-json", "-m", "all"); err != nil {
		return nil, fmt.Errorf("listing modules failed: %w", err)
	}
	defer buf.Reset()

	return parseModules(buf)
}

// ListAllModules ...
func (m *mod) ListAllModules(path string) ([]models.Module, error) {
	modules, err := m.ListModules(path)
	if err != nil {
		return nil, err
	}

	bufGraph := new(bytes.Buffer)
	if err := helper.ExecCMD(path, bufGraph, "go", "mod", "graph"); err != nil {
		return nil, fmt.Errorf("listing dependencies failed: %w", err)
	}
	defer bufGraph.Reset()

	if err := buildDependenciesGraph(modules, bufGraph); err != nil {
		return nil, fmt.Errorf("listing dependencies failed: %w", err)
	}

	return modules, nil
}

// parseModules parses the output of `go list -json -m` into a Module slice
func parseModules(reader io.Reader) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	jsonDecoder := json.NewDecoder(reader)

	// Output is not a JSON array, so we have to parse one object after another
	for {
		var mod models.Module
		if err := jsonDecoder.Decode(&mod); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		mod.Name = mod.Path
		mod.PackageURL = genUrl(mod)
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(mod.Path),
		}
		licensePkg, err := helper.GetLicenses(mod.LocalPath)
		if err == nil {
			mod.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
			mod.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
			if !helper.LicenseSPDXExists(licensePkg.ID) {
				licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
				mod.OtherLicense = append(mod.OtherLicense, licensePkg)
			}
		}
		mod.Modules = map[string]*models.Module{}
		modules = append(modules, mod)
	}
	return modules, nil
}

func buildDependenciesGraph(modules []models.Module, reader io.Reader) error {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}
	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
	}

	scanner := bufio.NewScanner(reader)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) != 2 {
			return fmt.Errorf("expected two fields per line, but got %d: %s", len(fields), line)
		}

		moduleName := strings.Split(fields[0], "@")[0]
		if _, ok := moduleMap[moduleName]; !ok {
			continue
		}

		depName := strings.Split(fields[1], "@")[0]
		depModule, ok := moduleMap[depName]
		if !ok {
			continue
		}

		modules[moduleIndex[moduleName]].Modules[depName] = &models.Module{
			Name:             depModule.Name,
			Version:          depModule.Version,
			Path:             depModule.Path,
			LocalPath:        depModule.LocalPath,
			Supplier:         depModule.Supplier,
			PackageURL:       depModule.PackageURL,
			CheckSum:         depModule.CheckSum,
			PackageHomePage:  depModule.PackageHomePage,
			LicenseConcluded: depModule.LicenseConcluded,
			LicenseDeclared:  depModule.LicenseDeclared,
			CommentsLicense:  depModule.CommentsLicense,
			OtherLicense:     depModule.OtherLicense,
			Copyright:        depModule.Copyright,
			PackageComment:   depModule.PackageComment,
			Root:             depModule.Root,
		}
	}

	return nil
}

func genUrl(m models.Module) string {
	path := m.Path + "@" + m.Version
	if m.Version == "" {
		path = m.Path
	}

	return "pkg:golang/" + path
}

// this is just a test
func readCheckSum(content string) string {
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

func decoratePath(m models.Module) string {
	if m.Version == "" {
		return m.Path
	}
	return m.Path + "@" + m.Version
}
