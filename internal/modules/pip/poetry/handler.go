// SPDX-License-Identifier: Apache-2.0

package poetry

import (
	"errors"
	"fmt"
	"path/filepath"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type poetry struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
}

const cmdName = "poetry"
const manifestSetupPy = "setup.py"
const manifestSetupCfg = "setup.cfg"
const manifestFile = "pyproject.toml"
const manifestLockFile = "Poetry.lock"

var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `poetry install` or `poetry update` might solve the issue.")
var errBuildlingModuleDependencies = errors.New("Error building modules dependencies")
var errNoPipCommand = errors.New("No poetry command")
var errVersionNotFound = errors.New("Python version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

// New ...
func New() *poetry {
	return &poetry{
		metadata: models.PluginMetadata{
			Name:       "The Python Package Index (PyPI)",
			Slug:       "pip",
			Manifest:   []string{manifestLockFile},
			ModulePath: []string{},
		},
	}
}

// Get Metadata ...
func (m *poetry) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// Is Valid ...
func (m *poetry) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// Has Modules Installed ...
func (m *poetry) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// Get Version ...
func (m *poetry) GetVersion() (string, error) {
	if err := m.buildCmd(VersionCmd, m.basepath); err != nil {
		return "", err
	}
	version, err := m.command.Output()
	if err != nil {
		return "Python", errVersionNotFound
	}
	return version, err
}

// Set Root Module ...
func (m *poetry) SetRootModule(path string) error {
	m.basepath = path
	return nil
}

// Get Root Module ...
func (m *poetry) GetRootModule(path string) (*models.Module, error) {
	fmt.Println("In GetRootModule")
	return nil, nil
}

// List Used Modules...
func (m *poetry) ListUsedModules(path string) ([]models.Module, error) {
	fmt.Println("In ListUsedModules")
	return nil, nil
}

// List Modules With Deps ...
func (m *poetry) ListModulesWithDeps(path string) ([]models.Module, error) {
	fmt.Println("In ListModulesWithDeps")
	return nil, nil
}

func (m *poetry) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if cmdArgs[0] != cmdName {
		return errNoPipCommand
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}
