package npm

import (
	"errors"
	"path/filepath"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type npm struct {
	metadata models.PluginMetadata
}

var errDependenciesNotFound = errors.New("Please install dependencies by running go mod vendor")

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
		if helper.FileExists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *npm) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.FileExists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
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
