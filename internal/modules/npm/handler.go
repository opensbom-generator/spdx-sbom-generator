// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"os/exec"
	"path/filepath"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type npm struct {
	metadata models.PluginMetadata
}

// New ...
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

// GetMetadata ...
func (m *npm) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *npm) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *npm) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion ...
func (m *npm) GetVersion() (string, error) {
	output, err := exec.Command("npm", "--version").Output()
	if err != nil {
		return "", err
	}

	return string(output), nil
}

// SetRootModule ...
func (m *npm) SetRootModule(path string) error {
	return nil
}

// GetRootModule ...
func (m *npm) GetRootModule(path string) (*models.Module, error) {
	return nil, nil
}

// ListUsedModules...
func (m *npm) ListUsedModules(path string) ([]models.Module, error) {
	return nil, nil
}

// ListModulesWithDeps ...
func (m *npm) ListModulesWithDeps(path string) ([]models.Module, error) {
	return nil, nil
}
