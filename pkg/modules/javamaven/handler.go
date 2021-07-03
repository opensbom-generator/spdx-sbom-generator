// SPDX-License-Identifier: Apache-2.0

package javamaven

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"log"
	"os/exec"
	"path/filepath"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

type javamaven struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

// New ...
func New() *javamaven {
	return &javamaven{
		metadata: models.PluginMetadata{
			Name:     "Java Maven",
			Slug:     "Java-Maven",
			Manifest: []string{"pom.xml"},
			// TODO: instead of vendor folder what to mention for java project
			// Currently checking for mvn executable path in PATH variable
			ModulePath: []string{"."},
		},
	}
}

// GetMetadata ...
func (m *javamaven) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// SetRootModule ...
func (m *javamaven) SetRootModule(path string) error {
	module, err := m.getModule(path)
	if err != nil {
		return err
	}

	m.rootModule = &module

	return nil
}

// IsValid ...
func (m *javamaven) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *javamaven) HasModulesInstalled(path string) error {
	// TODO: How to verify is java project is build
	// Enforcing mvn path to be set in PATH variable
	fname, err := exec.LookPath("mvn")
	if err != nil {
		log.Println(err)
		return err
	}

	_, err = filepath.Abs(fname)
	if err != nil {
		log.Println(err)
		return err
	}

	return nil
}

// GetVersion...
func (m *javamaven) GetVersion() (string, error) {
	err := m.buildCmd(VersionCmd, ".")
	if err != nil {
		return "", err
	}

	return m.command.Output()
}

// GetRootModule...
func (m *javamaven) GetRootModule(path string) (*models.Module, error) {
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
func (m *javamaven) ListUsedModules(path string) ([]models.Module, error) {
	modules, err := convertPOMReaderToModules(path, true)

	if err != nil {
		log.Println(err)
		return modules, err
	}

	return modules, nil
}

// ListModulesWithDeps ...
func (m *javamaven) ListModulesWithDeps(path string) ([]models.Module, error) {
	modules, err := m.ListUsedModules(path)
	if err != nil {
		return nil, err
	}

	tdList, err := getTransitiveDependencyList()
	if err != nil {
		fmt.Println("error in getting mvn transitive dependency tree and parsing it")
		return nil, err
	}

	buildDependenciesGraph(modules, tdList)

	return modules, nil
}

func (m *javamaven) getModule(path string) (models.Module, error) {
	modules, err := convertPOMReaderToModules(path, false)

	if err != nil {
		log.Println(err)
		return models.Module{}, err
	}

	if len(modules) == 0 {
		return models.Module{}, errFailedToConvertModules
	}

	return modules[0], nil
}

func (m *javamaven) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}

func readCheckSum(content string) string {
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}
