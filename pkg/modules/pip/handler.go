// SPDX-License-Identifier: Apache-2.0

package pip

import (
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/pip/pipenv"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/pip/poetry"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/pip/pyenv"
)

type pip struct {
	plugin models.IPlugin
}

// New ...
func New() *pip {
	return &pip{
		plugin: nil,
	}
}

// Get Metadata ...
func (m *pip) GetMetadata() models.PluginMetadata {
	return m.plugin.GetMetadata()
}

// Is Valid ...
func (m *pip) IsValid(path string) bool {
	if p := pipenv.New(); p.IsValid(path) {
		m.plugin = p
		return true
	}

	if p := poetry.New(); p.IsValid(path) {
		m.plugin = p
		return true
	}

	if p := pyenv.New(); p.IsValid(path) {
		m.plugin = p
		return true
	}

	return false
}

// Has Modules Installed ...
func (m *pip) HasModulesInstalled(path string) error {
	return m.plugin.HasModulesInstalled(path)
}

// Get Version ...
func (m *pip) GetVersion() (string, error) {
	return m.plugin.GetVersion()
}

// Set Root Module ...
func (m *pip) SetRootModule(path string) error {
	return m.plugin.SetRootModule(path)
}

// Get Root Module ...
func (m *pip) GetRootModule(path string) (*models.Module, error) {
	return m.plugin.GetRootModule(path)
}

// List Used Modules...
func (m *pip) ListUsedModules(path string) ([]models.Module, error) {
	return m.plugin.ListUsedModules(path)
}

// List Modules With Deps ...
func (m *pip) ListModulesWithDeps(path string, globalSettingFile string) ([]models.Module, error) {
	return m.plugin.ListModulesWithDeps(path, globalSettingFile)
}
