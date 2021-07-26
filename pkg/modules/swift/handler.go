// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"bytes"
	"encoding/json"
	"os/exec"
	"path/filepath"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

type pkg struct {
	metadata models.PluginMetadata
}

const (
	ManifestFile   string = "Package.swift"
	BuildDirectory string = ".build"
)

// New creates a new Swift package instance
func New() *pkg {
	return &pkg{
		metadata: models.PluginMetadata{
			Name:       "Swift Package Manager",
			Slug:       "swift",
			Manifest:   []string{ManifestFile},
			ModulePath: []string{BuildDirectory},
		},
	}
}

// GetVersion returns Swift language version
func (m *pkg) GetVersion() (string, error) {
	cmd := exec.Command("swift", "--version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	version := string(output)

	return version, nil
}

// GetMetadata returns root package information base on path given
func (m *pkg) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// SetRootModule sets root package information base on path given
func (m *pkg) SetRootModule(path string) error {
	return nil
}

// GetRootModule returns root package information base on path given
func (m *pkg) GetRootModule(path string) (*models.Module, error) {
	cmd := exec.Command("swift", "package", "describe", "--type", "json")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var description SwiftPackageDescription
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&description); err != nil {
		return nil, err
	}

	mod := description.Module()

	return mod, nil
}

// ListUsedModules fetches and lists
// all packages required by the project
// in the given project directory,
// this is a plain list of all used modules
// (no nested or tree view)
func (m *pkg) ListUsedModules(path string) ([]models.Module, error) {
	cmd := exec.Command("swift", "package", "show-dependencies", "--disable-automatic-resolution", "--format", "json")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var root SwiftPackageDependency
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&root); err != nil {
		return nil, err
	}

	var dependencies []SwiftPackageDependency

	var recurse func(SwiftPackageDependency)
	recurse = func(dep SwiftPackageDependency) {
		for _, nested := range dep.Dependencies {
			dependencies = append(dependencies, nested)
			recurse(nested)
		}
	}
	recurse(root)

	var collection []models.Module
	for _, dep := range dependencies {
		mod := dep.Module()
		collection = append(collection, *mod)
	}

	return collection, nil
}

// ListModulesWithDeps fetches and lists all packages
// (root and direct dependencies)
// required by the project in the given project directory (side-by-side),
// this is a one level only list of all used modules,
// and each with its direct dependency only
// (similar output to ListUsedModules but with direct dependency only)
func (m *pkg) ListModulesWithDeps(path string) ([]models.Module, error) {
	var collection []models.Module

	mod, err := m.GetRootModule(path)
	if err != nil {
		return nil, err
	}
	collection = append(collection, *mod)

	cmd := exec.Command("swift", "package", "show-dependencies", "--disable-automatic-resolution", "--format", "json")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return nil, err
	}

	var root SwiftPackageDependency
	if err := json.NewDecoder(bytes.NewReader(output)).Decode(&root); err != nil {
		return nil, err
	}

	for _, dep := range root.Dependencies {
		mod := dep.Module()
		collection = append(collection, *mod)
	}

	return collection, nil
}

// IsValid checks if the project dependency file provided in the contract exists
func (m *pkg) IsValid(path string) bool {
	return helper.Exists(filepath.Join(path, ManifestFile))
}

// HasModulesInstalled checks whether
// the current project (based on given path)
// has the dependent packages installed
func (m *pkg) HasModulesInstalled(path string) error {
	if helper.Exists(filepath.Join(path, BuildDirectory)) {
		return nil
	}

	return errDependenciesNotFound
}
