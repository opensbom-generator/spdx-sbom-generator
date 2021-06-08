// SPDX-License-Identifier: Apache-2.0

package poetry

import (
	"errors"
	"path/filepath"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/modules/pip/worker"
	"strings"
)

const cmdName = "poetry"
const manifestFile = "pyproject.toml"
const manifestLockFile = "poetry.lock"
const placeholderPkgName = "{PACKAGE}"

var errDependenciesNotFound = errors.New("Unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `poetry install` or `poetry update`")
var errBuildlingModuleDependencies = errors.New("Error building modules dependencies")
var errNoPipCommand = errors.New("No poetry command")
var errVersionNotFound = errors.New("Python version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

type poetry struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
	pkgs       []worker.Packages
	metainfo   map[string]worker.Metadata
}

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
	if err := m.buildCmd(ModulesCmd, m.basepath); err != nil {
		return err
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 && worker.IsRequirementMeet(false, result) {
		m.pkgs = worker.LoadModules(result)
		return nil
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
func (m *poetry) ListUsedModules(path string) ([]models.Module, error) {
	var modules []models.Module
	mod, err := m.GetRootModule(path)
	if err == nil {
		modules = append(modules, *mod)
	}
	decoder := worker.NewMetadataDecoder(m.GetPackageDetails)
	nonroot := decoder.ConvertMetadataToModules(false, m.pkgs, &modules)
	m.metainfo = worker.MergeMetadataMap(m.metainfo, nonroot)
	modules = worker.RemoveDuplicateRootModule(modules)
	return modules, nil
}

// List Modules With Deps ...
func (m *poetry) ListModulesWithDeps(path string) ([]models.Module, error) {
	modules, err := m.ListUsedModules(path)
	if err != nil {
		return nil, err
	}
	if err := worker.BuildDependencyGraph(&modules, &m.metainfo); err != nil {
		return nil, err
	}
	return modules, err
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

func (m *poetry) GetPackageDetails(packageName string) (string, error) {
	metatdataCmd := command(strings.ReplaceAll(string(MetadataCmd), placeholderPkgName, packageName))

	m.buildCmd(metatdataCmd, m.basepath)
	result, err := m.command.Output()
	if err != nil {
		return "", err
	}

	return result, nil
}

func (m *poetry) PushRootModuleToVenv() bool {
	if err := m.buildCmd(InstallRootModuleCmd, m.basepath); err != nil {
		return false
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 {
		return true
	}
	return false
}

func (m *poetry) fetchRootModule(path string) (models.Module, error) {
	var pkgs []worker.Packages
	var pkg worker.Packages
	var modules []models.Module

	split := strings.Split(path, "/")
	pkg.Name = split[len(split)-1]
	pkg.Version = "0.0.0"
	pkgs = append(pkgs, pkg)

	rootModuleState := m.PushRootModuleToVenv()
	if rootModuleState {
		decoder := worker.NewMetadataDecoder(m.GetPackageDetails)
		m.metainfo = decoder.ConvertMetadataToModules(true, pkgs, &modules)
	}
	return modules[0], nil
}
