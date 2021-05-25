package composer

import (
	"bytes"
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

// rest of the file below
type composer struct {
	metadata models.PluginMetadata
}
var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `go mod vendor` or `go get` might solve the issue.")


// New ...
func New() *composer {
	return &composer{
		metadata: models.PluginMetadata{
			Name:       "composer Package Manager",
			Slug:       "composer",
			Manifest:   []string{"composer.json"},
			ModulePath: []string{"vendor"},
		},
	}
}

// GetMetadata ...
func (m *composer) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *composer) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *composer) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.FileExists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion ...
func (m *composer) GetVersion() (string, error) {
	cmd := exec.Command("composer", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))

	if fields[0] != "Composer" || fields[1] != "version" {
		return "", fmt.Errorf("unexpected output format: %s", output)
	}

	return fields[2], nil
}

// GetModule ...
func (m *composer) GetModule(path string) ([]models.Module, error) {
	return nil, nil
}

// ListAllModules ...
func (m *composer) ListAllModules(path string) ([]models.Module, error) {
	return nil, nil
}

// ListModules ...
func (m *composer) ListModules(path string) ([]models.Module, error) {

	var modules []models.Module
	var err error

	buf := new(bytes.Buffer)
	err = helper.ExecCMD(path, buf, "composer", "show", "-i", "-f", "json")

	if err != nil {
		return nil, fmt.Errorf("listing modules failed: %w", err)
	}

	defer buf.Reset()

	modules, err = parseModules(buf)
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	return modules, nil
}

// parseModules parses the output of `go list -json -m` into a Module slice
func parseModules(reader io.Reader) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	var composerModules models.ComposerModules

	err := json.NewDecoder(reader).Decode(&composerModules)
	if errors.Is(err, io.EOF) {
		return nil, err
	}

	for _, installed := range composerModules.Installed {
		var mod models.Module
		mod.Name = getName(installed.Name)
		mod.PackageURL = genUrl(installed.Name)
		mod.Version = installed.Version
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     "",
		}
		modules = append(modules, mod)
	}

	return modules, nil

}

func getName(moduleName string) string {

	s := strings.Split(moduleName, "/")

	return s[1]
}
func genUrl(path string) string {

	return "https://packagist.org/packages/" + path
}
