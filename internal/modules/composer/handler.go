package composer

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

var COMPOSER_LOCK_FILE_NAME = "composer.lock"
var COMPOSER_JSON_FILE_NAME = "composer.json"
var COMPOSER_VENDOR_FOLDER = "vendor"

type composer struct {
	metadata models.PluginMetadata
}

var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `composer install` might solve the issue.")

// New ...
func New() *composer {
	return &composer{
		metadata: models.PluginMetadata{
			Name:       "composer Package Manager",
			Slug:       "composer",
			Manifest:   []string{COMPOSER_JSON_FILE_NAME},
			ModulePath: []string{COMPOSER_VENDOR_FOLDER},
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
	return m.ListModules(path)
}

// ListModules ...
func (m *composer) ListModules(path string) ([]models.Module, error) {

	modules, err := getModulesFromComposerLockFile()
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	treeList, err := getTreeListFromComposerShowTree(path)
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	for _, treeComponent := range treeList.Installed {
		addTreeComponentsToModule(treeComponent, modules)
	}

	return modules, nil
}
