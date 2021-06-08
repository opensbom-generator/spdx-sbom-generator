// SPDX-License-Identifier: Apache-2.0

package pyenv

import (
	"errors"
	"path/filepath"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/modules/pip/worker"
	"strings"
)

const cmdName = "python"
const manifestFile = "requirements.txt"
const placeholderPkgName = "{PACKAGE}"

var errDependenciesNotFound = errors.New("Unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `pip install -r requirements.txt`")
var errBuildlingModuleDependencies = errors.New("Error building modules dependencies")
var errNoPipCommand = errors.New("No pyenv command")
var errVersionNotFound = errors.New("Python version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

type pyenv struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
	pkgs       []worker.Packages
	metainfo   map[string]worker.Metadata
}

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
	state, venv, venvpath := worker.SearchVenv(path)
	if state && len(venv) > 0 {
		runme = true
		m.metadata.ModulePath = append(m.metadata.ModulePath, venvpath)
	}
	if runme {
		dir := m.GetExecutableDir()
		if err := m.buildCmd(ModulesCmd, dir); err != nil {
			return err
		}
		result, err := m.command.Output()
		if err == nil && len(result) > 0 && worker.IsRequirementMeet(false, result) {
			m.pkgs = worker.LoadModules(result)
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
	if m.rootModule == nil {
		module, err := m.fetchRootModule(path)
		if err != nil {
			return nil, err
		}
		m.rootModule = &module
	}
	return m.rootModule, nil
}

// List Used Modules...
func (m *pyenv) ListUsedModules(path string) ([]models.Module, error) {
	var modules []models.Module
	mod, err := m.GetRootModule(path)
	if err == nil {
		modules = append(modules, *mod)
	}
	decoder := worker.NewMetadataDecoder(m.GetPackageDetails)
	nonroot := decoder.ConvertMetadataToModules(false, m.pkgs, &modules)
	m.metainfo = worker.MergeMetadataMap(m.metainfo, nonroot)
	return modules, nil
}

// List Modules With Deps ...
func (m *pyenv) ListModulesWithDeps(path string) ([]models.Module, error) {
	modules, err := m.ListUsedModules(path)
	if err != nil {
		return nil, err
	}
	if err := worker.BuildDependencyGraph(&modules, &m.metainfo); err != nil {
		return nil, err
	}
	return modules, err
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

func (m *pyenv) GetExecutableDir() string {
	if len(m.metadata.ModulePath[0]) > 0 {
		return m.metadata.ModulePath[0]
	}
	return m.basepath
}

func (m *pyenv) GetPackageDetails(packageName string) (string, error) {
	metatdataCmd := command(strings.ReplaceAll(string(MetadataCmd), placeholderPkgName, packageName))
	dir := m.GetExecutableDir()

	m.buildCmd(metatdataCmd, dir)
	result, err := m.command.Output()
	if err != nil {
		return "", err
	}

	return result, nil
}

func (m *pyenv) PushRootModuleToVenv() bool {
	dir := m.GetExecutableDir()
	if err := m.buildCmd(InstallRootModuleCmd, dir); err != nil {
		return false
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 {
		return true
	}
	return false
}

func (m *pyenv) fetchRootModule(path string) (models.Module, error) {
	var pkgs []worker.Packages
	var modules []models.Module
	var rootModuleState bool

	if worker.IsValidRootModule(path) {
		rootModuleState = m.PushRootModuleToVenv()
	}
	if rootModuleState {
		dir := m.GetExecutableDir()
		m.buildCmd(RootModuleCmd, dir)
		result, err := m.command.Output()
		if err == nil && len(result) > 0 && worker.IsRequirementMeet(true, result) {
			pkgs = worker.LoadModules(result)
		}
		decoder := worker.NewMetadataDecoder(m.GetPackageDetails)
		m.metainfo = decoder.ConvertMetadataToModules(true, pkgs, &modules)
	}
	return modules[0], nil
}
