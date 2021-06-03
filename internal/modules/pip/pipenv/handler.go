// SPDX-License-Identifier: Apache-2.0

package pipenv

import (
	"errors"
	"fmt"
	"path/filepath"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type pipenv struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
}

const cmdName = "pipenv"
const manifestSetupPy = "setup.py"
const manifestSetupCfg = "setup.cfg"
const manifestFile = "Pipfile"
const manifestLockFile = "Pipfile.lock"

var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `pipenv install` might solve the issue.")
var errBuildlingModuleDependencies = errors.New("Error building modules dependencies")
var errNoPipCommand = errors.New("No pipenv command")
var errVersionNotFound = errors.New("version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

// New ...
func New() *pipenv {
	return &pipenv{
		metadata: models.PluginMetadata{
			Name:       "The Python Package Index (PyPI)",
			Slug:       "pip",
			Manifest:   []string{manifestLockFile},
			ModulePath: []string{},
		},
	}
}

// Get Metadata ...
func (m *pipenv) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// Is Valid ...
func (m *pipenv) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// Has Modules Installed ...
func (m *pipenv) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// Get Version ...
func (m *pipenv) GetVersion() (string, error) {
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
func (m *pipenv) SetRootModule(path string) error {
	m.basepath = path
	return nil
}

// Get Root Module ...
func (m *pipenv) GetRootModule(path string) (*models.Module, error) {
	fmt.Println("In GetRootModule")
	return nil, nil
}

// List Used Modules...
func (m *pipenv) ListUsedModules(path string) ([]models.Module, error) {
	fmt.Println("In ListUsedModules")
	return nil, nil
}

// List Modules With Deps ...
func (m *pipenv) ListModulesWithDeps(path string) ([]models.Module, error) {
	fmt.Println("In ListModulesWithDeps")
	return nil, nil
}

func (m *pipenv) buildCmd(cmd command, path string) error {
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
