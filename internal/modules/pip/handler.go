// SPDX-License-Identifier: Apache-2.0

package pip

import (
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/modules/pip/pipenv"
	"spdx-sbom-generator/internal/modules/pip/poetry"
	"spdx-sbom-generator/internal/modules/pip/pyenv"
)

type pip struct {
	pip models.IPlugin
}

// Initiate the new pip plugin
func New() *pip {
	return &pip{
		pip: nil,
	}
}

// Get Metadata ...
func (m *pip) GetMetadata() models.PluginMetadata {
	return m.pip.GetMetadata()
}

// Is Valid ...
func (m *pip) IsValid(path string) bool {
	if p := pipenv.New(); p.IsValid(path) {
		m.pip = p
		return true
	}

	if p := poetry.New(); p.IsValid(path) {
		m.pip = p
		return true
	}

	if p := pyenv.New(); p.IsValid(path) {
		m.pip = p
		return true
	}

	return false
}

// Has Modules Installed ...
func (m *pip) HasModulesInstalled(path string) error {
	return m.pip.HasModulesInstalled(path)
}

// Get Version ...
func (m *pip) GetVersion() (string, error) {
	return m.pip.GetVersion()
}

// Set Root Module ...
func (m *pip) SetRootModule(path string) error {
	return m.pip.SetRootModule(path)
}

// Get Root Module ...
func (m *pip) GetRootModule(path string) (*models.Module, error) {
	return m.pip.GetRootModule(path)
}

// List Used Modules...
func (m *pip) ListUsedModules(path string) ([]models.Module, error) {
	return m.pip.ListUsedModules(path)
}

// List Modules With Deps ...
func (m *pip) ListModulesWithDeps(path string) ([]models.Module, error) {
	return m.pip.ListModulesWithDeps(path)
}
