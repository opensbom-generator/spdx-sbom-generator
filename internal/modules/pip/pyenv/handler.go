// SPDX-License-Identifier: Apache-2.0

package pyenv

import (
	"errors"
	"fmt"
	"path/filepath"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/modules/pip/worker"
	"strings"
)

type pyenv struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
}

const cmdName = "python"
const manifestSetupPy = "setup.py"
const manifestSetupCfg = "setup.cfg"
const manifestFile = "requirements.txt"

var errDependenciesNotFound = errors.New("There are no components in the BOM. The project may not contain dependencies installed. Please install Modules before running spdx-sbom-generator, e.g.: `pip install -r requirements.txt` might solve the issue.")
var errBuildlingModuleDependencies = errors.New("Error building modules dependencies")
var errNoPipCommand = errors.New("No pyenv command")
var errVersionNotFound = errors.New("Python version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

// New ...
func New() *pyenv {
	return &pyenv{
		metadata: models.PluginMetadata{
			Name:       "The Python Package Index (PyPI)",
			Slug:       "pip",
			Manifest:   []string{manifestFile},
			ModulePath: []string{},
		},
	}
}

// Get Metadata ...
func (m *pyenv) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// Is Valid ...
func (m *pyenv) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// Has Modules Installed ...
func (m *pyenv) HasModulesInstalled(path string) error {
	runme := false
	dir := m.basepath

	state, venv, venvpath := worker.SearchVenv(path)
	if state && len(venv) > 0 {
		runme = true
		m.metadata.ModulePath = append(m.metadata.ModulePath, venvpath)
		dir = m.metadata.ModulePath[0]
	}

	if runme {
		if err := m.buildCmd(ModulesCmd, dir); err != nil {
			return err
		}
		result, err := m.command.Output()
		if err == nil && len(result) > 0 && worker.IsRequirementMeet(result) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// Get Version ...
func (m *pyenv) GetVersion() (string, error) {
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
func (m *pyenv) SetRootModule(path string) error {
	m.basepath = path
	return nil
}

// Get Root Module ...
func (m *pyenv) GetRootModule(path string) (*models.Module, error) {
	fmt.Println("In GetRootModule")
	return nil, nil
}

// List Used Modules...
func (m *pyenv) ListUsedModules(path string) ([]models.Module, error) {
	fmt.Println("In ListUsedModules")
	return nil, nil
}

// List Modules With Deps ...
func (m *pyenv) ListModulesWithDeps(path string) ([]models.Module, error) {
	fmt.Println("In ListModulesWithDeps")
	return nil, nil
}

func (m *pyenv) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if !strings.Contains(cmdArgs[0], cmdName) {
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
