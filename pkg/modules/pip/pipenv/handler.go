// SPDX-License-Identifier: Apache-2.0

package pipenv

import (
	"errors"
	"path/filepath"
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/pip/worker"
)

const cmdName = "pipenv"
const manifestFile = "Pipfile"
const manifestLockFile = "Pipfile.lock"
const placeholderPkgName = "{PACKAGE}"
const packageSrcLocation = "/src/"
const packageSiteLocation = "/site-packages"

var errDependenciesNotFound = errors.New("Unable to generate SPDX file: no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `pipenv install` or `pipenv update`")
var errBuildlingModuleDependencies = errors.New("Error building module dependencies")
var errNoPipCommand = errors.New("Cannot find the pipenv command")
var errVersionNotFound = errors.New("Python version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

type pipenv struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
	version    string
	pkgs       []worker.Packages
	metainfo   map[string]worker.Metadata
	allModules []models.Module
}

// New ...
func New() *pipenv {
	return &pipenv{
		metadata: models.PluginMetadata{
			Name:       "The Python Package Index (PyPI)",
			Slug:       "pipenv",
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
	if err := m.buildCmd(ModulesCmd, m.basepath); err != nil {
		return err
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 && worker.IsRequirementMeet(result) {
		return nil
	}
	return errDependenciesNotFound
}

// Get Version ...
func (m *pipenv) GetVersion() (string, error) {
	if err := m.buildCmd(VersionCmd, m.basepath); err != nil {
		return "", err
	}
	version, err := m.command.Output()
	m.version = worker.GetShortPythonVersion(version)
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
	if m.rootModule == nil {
		module := m.fetchRootModule()
		m.rootModule = &module
	}
	return m.rootModule, nil
}

// List Used Modules...
func (m *pipenv) ListUsedModules(path string) ([]models.Module, error) {
	if err := m.LoadModuleList(path); err != nil {
		return m.allModules, errFailedToConvertModules
	}

	decoder := worker.NewMetadataDecoder(m.GetPackageDetails)
	metainfo, err := decoder.ConvertMetadataToModules(m.pkgs, &m.allModules)
	if err != nil {
		return m.allModules, err
	}

	m.metainfo = metainfo
	return m.allModules, nil
}

// List Modules With Deps ...
func (m *pipenv) ListModulesWithDeps(path string, globalSettingFile string) ([]models.Module, error) {
	modules, err := m.ListUsedModules(path)
	if err != nil {
		return nil, err
	}
	m.GetRootModule(path)
	if err := worker.BuildDependencyGraph(&m.allModules, &m.metainfo); err != nil {
		return nil, err
	}
	return modules, err
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

func (m *pipenv) GetPackageDetails(packageNameList string) (string, error) {
	metatdataCmd := command(strings.ReplaceAll(string(MetadataCmd), placeholderPkgName, packageNameList))

	m.buildCmd(metatdataCmd, m.basepath)
	result, err := m.command.Output()
	if err != nil {
		return "", err
	}

	return result, nil
}

func (m *pipenv) PushRootModuleToVenv() (bool, error) {
	if err := m.buildCmd(InstallRootModuleCmd, m.basepath); err != nil {
		return false, err
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 {
		return true, err
	}
	return false, nil
}

func (m *pipenv) markRootModue() {
	for i, pkg := range m.pkgs {
		if worker.IsRootModule(pkg, m.metadata.Slug) {
			m.pkgs[i].Root = true
			break
		}
	}
}

func (m *pipenv) LoadModuleList(path string) error {
	var state bool
	var err error

	if worker.IsValidRootModule(path) {
		state, err = m.PushRootModuleToVenv()
		if err != nil && !state {
			return err
		}
		m.buildCmd(ModulesCmd, m.basepath)
		result, err := m.command.Output()
		if err == nil && len(result) > 0 && worker.IsRequirementMeet(result) {
			m.pkgs = worker.LoadModules(result, m.version)
			m.markRootModue()
		}
		return err
	}
	return err
}

func (m *pipenv) fetchRootModule() models.Module {
	for _, mod := range m.allModules {
		if mod.Root {
			return mod
		}
	}
	return models.Module{}
}
