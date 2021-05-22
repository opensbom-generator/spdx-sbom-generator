package npm

import (
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
			Manifest:   "package.json",
			ModulePath: "node_modules",
		},
	}
}

// GetMetadata ...
func (m *npm) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *npm) IsValid(path string) bool {
	return helper.FileExists(filepath.Join(path, m.metadata.Manifest))
}

// HasModulesInstalled ...
func (m *npm) HasModulesInstalled(path string) bool {
	return helper.FileExists(filepath.Join(path, m.metadata.ModulePath))
}

// GetVersion ...
func (m *npm) GetVersion() (string, error) {
	return "NPM VERSION", nil
}

// GetModule ...
func (m *npm) GetModule(path string) ([]models.Module, error) {
	return nil, nil
}

// ListModules ...
func (m *npm) ListModules(path string) ([]models.Module, error) {
	return nil, nil
}

// ListAllModules ...
func (m *npm) ListAllModules(path string) ([]models.Module, error) {
	return nil, nil
}
