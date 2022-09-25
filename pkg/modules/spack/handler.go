package spack

import (
	"os/exec"
	"path/filepath"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

// This model of spack assumes we are interested in modules installed
// in a spack root. This could eventually support views and environments
// if it is requested by a spdx-sbom-generator user.

type spack struct {
	metadata  models.PluginMetadata
	spackRoot string
}

// New creates a new spack plugin metadata registration
func New() *spack {
	return &spack{
		metadata: models.PluginMetadata{
			Name:       "Spack Package Manager",
			Slug:       "spack",
			Manifest:   []string{"spec.json"},
			ModulePath: []string{"opt"},
		},
	}
}

// GetMetadata is requied to return for the basic metadata interface
func (m *spack) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// SetRootModule sets root package information base on path given
// Spack is installed in one root, so here we look for it in the environment path
func (m *spack) SetRootModule(path string) error {

	// If we can't find it no big deal
	spackRoot, err := exec.LookPath("spack")
	if err != nil {
		return err
	}
	m.spackRoot = filepath.Dir(filepath.Dir(spackRoot))
	return nil
}

// IsValid determines if spack is installed
func (m *spack) IsValid(path string) bool {
	return m.SetRootModule(path) == nil
}

// HasModulesInstalled returns an error if no modules are installed, or spack isn't installed
func (m *spack) HasModulesInstalled(path string) error {

	// Cut out early if spack not installed
	if m.spackRoot == "" {
		return errSpackNotFound
	}

	// Look for .spack metadata directories - this top level has arch, package, metadata
	// E.g., opt/spack/linux-ubuntu20.04-skylake/gcc-9.4.0/sqlite-3.38.5-c5jzh2xkxz6xdqfyqle5zjpzqw5yh3wp/.spack
	// This iterates over the spack metadata directories
	for _, path := range m.getInstallPaths(m.installDir()) {

		// We can cut out and return nil (no error) after we find just one!
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[0])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion will return the version of spack installed
func (m *spack) GetVersion() (string, error) {
	output, err := exec.Command("spack", "--version").Output()
	if err != nil {
		return "", err
	}
	return string(output), nil
}

// GetRootModule ...
func (m *spack) GetRootModule(path string) (*models.Module, error) {
	return nil, nil
}

// ListUsedModules will list all package installs for spack
func (m *spack) ListUsedModules(path string) ([]models.Module, error) {

	var modules []models.Module
	if m.spackRoot == "" {
		return modules, errSpackNotFound
	}

	// TODO: if views/environment added, load here first
	modules, err := m.getModulesList()
	if err != nil {
		return nil, err
	}
	return modules, nil
}

// ListModulesWithDeps ...
func (m *spack) ListModulesWithDeps(path string, globalSettingFile string) ([]models.Module, error) {
	return m.ListUsedModules(path)
}
