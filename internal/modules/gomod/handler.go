// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"path/filepath"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type mod struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

// New ...
func New() *mod {
	return &mod{
		metadata: models.PluginMetadata{
			Name:       "Go Modules",
			Slug:       "go-mod",
			Manifest:   []string{"go.mod"},
			ModulePath: []string{"vendor"}, // todo Add other module source
		},
	}
}

// GetMetadata ...
func (m *mod) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// SetRootModule ...
func (m *mod) SetRootModule(path string) error {
	module, err := m.getModule(path)
	if err != nil {
		return err
	}

	m.rootModule = &module

	return nil
}

// IsValid ...
func (m *mod) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *mod) HasModulesInstalled(path string) error {
	for i := range m.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion...
func (m *mod) GetVersion() (string, error) {
	if err := m.buildCmd(VersionCmd, "."); err != nil {
		return "", err
	}

	return m.command.Output()
}

// GetRootModule...
func (m *mod) GetRootModule(path string) (*models.Module, error) {
	if m.rootModule == nil {
		module, err := m.getModule(path)
		if err != nil {
			return nil, err
		}

		m.rootModule = &module
	}

	return m.rootModule, nil
}

// ListUsedModules...
func (m *mod) ListUsedModules(path string) ([]models.Module, error) {
	if err := m.buildCmd(ModulesCmd, path); err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return nil, err
	}
	defer buffer.Reset()

	modules := []models.Module{}
	if err := NewDecoder(buffer).ConvertJSONReaderToModules(&modules); err != nil {
		return nil, err
	}

	return modules, nil
}

// ListModulesWithDeps ...
func (m *mod) ListModulesWithDeps(path string) ([]models.Module, error) {
	modules, err := m.ListUsedModules(path)
	if err != nil {
		return nil, err
	}

	if err := m.buildCmd(GraphModuleCmd, path); err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return nil, err
	}
	defer buffer.Reset()

	if err := NewDecoder(buffer).ConvertPlainReaderToModules(modules); err != nil {
		return nil, err
	}

	return modules, nil
}

func (m *mod) getModule(path string) (models.Module, error) {
	if err := m.buildCmd(RootModuleCmd, path); err != nil {
		return models.Module{}, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return models.Module{}, err
	}
	defer buffer.Reset()

	modules := []models.Module{}
	if err := NewDecoder(buffer).ConvertJSONReaderToModules(&modules); err != nil {
		return models.Module{}, err
	}

	if len(modules) == 0 {
		return models.Module{}, errFailedToConvertModules
	}

	return modules[0], nil
}

func (m *mod) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if cmdArgs[0] != "go" {
		return errNoGoCommand
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}

// this is just a test
func readCheckSum(content string) string {
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}
