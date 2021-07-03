// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"path/filepath"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

type composer struct {
	metadata models.PluginMetadata
	command  *helper.Cmd
}

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
	modules, err := m.getModulesFromComposerLockFile(path)
	if err != nil {
		return nil, errFailedToReadComposerFile
	}

	treeList, err := m.getTreeListFromComposerShowTree(path)
	if err != nil {
		return nil, errFailedToShowComposerTree
	}

	for _, treeComponent := range treeList.Installed {
		addTreeComponentsToModule(treeComponent, modules)
	}

	return modules, nil
}
