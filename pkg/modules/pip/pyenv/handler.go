// SPDX-License-Identifier: Apache-2.0

package pyenv

import (
	"errors"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/pip/worker"
)

const cmdName = "python"
const osWin = "windows"
const osDarwin = "darwin"
const osLinux = "linux"
const winExecutable = "Scripts"
const lxExecutable = "bin"
const manifestFile = "requirements.txt"
const placeholderPkgName = "{PACKAGE}"
const placeholderExecutableName = "{executable}"

var errDependenciesNotFound = errors.New("Unable to generate SPDX file: no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `pip install -r requirements.txt`")
var errBuildlingModuleDependencies = errors.New("Error building module dependencies")
var errNoPipCommand = errors.New("Cannot find the python command")
var errVersionNotFound = errors.New("Python version not found")
var errFailedToConvertModules = errors.New("Failed to convert modules")

type pyenv struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
	basepath   string
	version    string
	pkgs       []worker.Packages
	metainfo   map[string]worker.Metadata
	allModules []models.Module
	venv       string
}

// New ...
func New() *pyenv {
	return &pyenv{
		metadata: models.PluginMetadata{
			Name:       "The Python Package Index (PyPI)",
			Slug:       "pyenv",
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
	dir := m.GetExecutableDir()
	ModulesCmd := GetExecutableCommand(ModulesCmd)
	if err := m.buildCmd(ModulesCmd, dir); err != nil {
		return err
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 && worker.IsRequirementMeet(result) {
		return nil
	}
	return errDependenciesNotFound
}

// Get Version ...
func (m *pyenv) GetVersion() (string, error) {
	version := "Python"
	err := errVersionNotFound

	runme := m.fetchVenvPath()
	if runme {
		dir := m.GetExecutableDir()
		VersionCmd := GetExecutableCommand(VersionCmd)
		if err = m.buildCmd(VersionCmd, dir); err != nil {
			return "", err
		}
		version, err = m.command.Output()
		m.version = worker.GetShortPythonVersion(version)
		if err != nil {
			version = "Python"
			err = errVersionNotFound
		}
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
		module := m.fetchRootModule()
		m.rootModule = &module
	}
	return m.rootModule, nil
}

// List Used Modules...
func (m *pyenv) ListUsedModules(path string) ([]models.Module, error) {
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
func (m *pyenv) ListModulesWithDeps(path string) ([]models.Module, error) {
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
	MetadataCmd := GetExecutableCommand(MetadataCmd)
	MetadataCmd = command(strings.ReplaceAll(string(MetadataCmd), placeholderPkgName, packageName))
	dir := m.GetExecutableDir()

	m.buildCmd(MetadataCmd, dir)
	result, err := m.command.Output()
	if err != nil {
		return "", err
	}

	return result, nil
}

func (m *pyenv) PushRootModuleToVenv() (bool, error) {
	dir := m.GetExecutableDir()
	InstallRootModuleCmd := GetExecutableCommand(InstallRootModuleCmd)
	if err := m.buildCmd(InstallRootModuleCmd, dir); err != nil {
		return false, err
	}
	result, err := m.command.Output()
	if err == nil && len(result) > 0 {
		return true, err
	}
	return false, nil
}

func (m *pyenv) markRootModue() {
	for i, pkg := range m.pkgs {
		if worker.IsRootModule(pkg, m.metadata.Slug) {
			m.pkgs[i].Root = true
			break
		}
	}
}

func (m *pyenv) LoadModuleList(path string) error {
	var state bool
	var err error

	if worker.IsValidRootModule(path) {
		state, err = m.PushRootModuleToVenv()
		if err != nil && !state {
			return err
		}
		dir := m.GetExecutableDir()
		ModulesCmd := GetExecutableCommand(ModulesCmd)
		m.buildCmd(ModulesCmd, dir)
		result, err := m.command.Output()
		if err == nil && len(result) > 0 && worker.IsRequirementMeet(result) {
			m.pkgs = worker.LoadModules(result, m.version)
			m.markRootModue()
		}
		return err
	}
	return err
}

func (m *pyenv) fetchRootModule() models.Module {
	for _, mod := range m.allModules {
		if mod.Root {
			return mod
		}
	}
	return models.Module{}
}

func (m *pyenv) fetchVenvPath() bool {
	state, venv, venvpath := worker.SearchVenv(m.basepath)
	if state && len(venv) > 0 {
		m.venv = venv
		m.metadata.ModulePath = append(m.metadata.ModulePath, venvpath)
		return true
	}
	return false
}

func GetExecutableCommand(cmd command) command {
	os := runtime.GOOS
	switch os {
	case osWin:
		return command(strings.ReplaceAll(string(cmd), placeholderExecutableName, winExecutable))
	default:
		return command(strings.ReplaceAll(string(cmd), placeholderExecutableName, lxExecutable))
	}
}
