// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"errors"
	"fmt"
	"path/filepath"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

var COMPOSER_LOCK_FILE_NAME = "composer.lock"
var COMPOSER_JSON_FILE_NAME = "composer.json"
var COMPOSER_VENDOR_FOLDER = "vendor"

type composer struct {
	metadata models.PluginMetadata
	command  *helper.Cmd
}

var errDependenciesNotFound = errors.New("no dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `composer install`")
var errNoComposerCommand = errors.New("no Composer command")

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
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *composer) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion ...
func (m *composer) GetVersion() (string, error) {
	if err := m.buildCmd(VersionCmd, "."); err != nil {
		return "", err
	}

	return m.command.Output()
}

func (m *composer) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if cmdArgs[0] != "composer" {
		return errNoComposerCommand
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}

// SetRootModule ...
func (m *composer) SetRootModule(path string) error {
	return nil
}

// GetRootModule ...
func (m *composer) GetRootModule(path string) (*models.Module, error) {
	return nil, nil
}

// ListModulesWithDeps ...
func (m *composer) ListModulesWithDeps(path string) ([]models.Module, error) {
	return m.ListUsedModules(path)
}

// ListUsedModules...
func (m *composer) ListUsedModules(path string) ([]models.Module, error) {
	modules, err := m.getModulesFromComposerLockFile()
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	treeList, err := m.getTreeListFromComposerShowTree(path)
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	for _, treeComponent := range treeList.Installed {
		addTreeComponentsToModule(treeComponent, modules)
	}

	return modules, nil
}
