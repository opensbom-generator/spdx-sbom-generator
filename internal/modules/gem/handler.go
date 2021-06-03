package gem

import (
	"errors"
	"fmt"
	"os/exec"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type gem struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

var errDependenciesNotFound = errors.New(
	`* Please install dependencies by running the following commands :
	1) bundle install
	2) bundle install --deployment
	3) bundle exec rake install
	4) run the spdx-sbom-generator tool command
`)


// New ...
func New() *gem {
	return &gem{
		metadata: models.PluginMetadata{
			Name:       "Bundler",
			Slug:       "bundler",
			Manifest:   []string{"Gemfile", "Gemfile.lock,gems.rb,gems.locked"},
			ModulePath: []string{"vendor/bundle"},
		},
	}
}

// GetMetadata ...
func (g *gem) GetMetadata() models.PluginMetadata {
	return g.metadata
}

// IsValid ...
func (g *gem) IsValid(path string) bool {
	for i := range g.metadata.Manifest {
		if helper.Exists(filepath.Join(path, g.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (g *gem) HasModulesInstalled(path string) error {
	for i := range g.metadata.ModulePath {
		if helper.Exists(filepath.Join(path, g.metadata.ModulePath[i])) {
			return nil
		}
	}
	return errDependenciesNotFound
}

// GetVersion ...
func (g *gem) GetVersion() (string, error) {
	cmd := exec.Command("Bundler", "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))

	if fields[0] != "Bundler" || fields[1] != "version" {
		return "", fmt.Errorf("unexpected output format: %s", output)
	}

	return fields[2], nil
}

// SetRootModule ...
func (g *gem) SetRootModule(path string) error {
	module, err := g.GetRootModule(path)
	if err != nil {
		return err
	}

	g.rootModule = module

	return nil
}

// GetRootModule...
func (g *gem) GetRootModule(path string) (*models.Module, error) {
	if err := g.HasModulesInstalled(path); err != nil{
		return &models.Module{},err
	}
	return GetGemRootModule(path)
}

// GetModule ...
func (g *gem) GetModule(path string) ([]models.Module, error) {
	return nil, nil
}

// ListUsedModules ...
func (g *gem) ListUsedModules(path string) ([]models.Module, error) {
	return g.ListModulesWithDeps(path)
}

// ListModulesWithDeps ...
func (g *gem) ListModulesWithDeps(path string) ([]models.Module, error) {
	if err := g.HasModulesInstalled(path); err != nil{
		return []models.Module{},err
	}
	return ListGemRootModule(path)
}
