// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"errors"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/javagradle"

	log "github.com/sirupsen/logrus"

	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/cargo"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/composer"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/gem"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/gomod"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/javamaven"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/npm"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/nuget"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/pip"
	"github.com/spdx/spdx-sbom-generator/pkg/modules/yarn"
)

var (
	errNoPluginAvailable   = errors.New("no plugin system available for current path")
	errNoModulesInstalled  = errors.New("there are no components in the BOM. The project may not contain dependencies, please install modules")
	errFailedToReadModules = errors.New("failed to read modules")
)

var registeredPlugins []models.IPlugin

func init() {
	registeredPlugins = append(registeredPlugins,
		cargo.New(),
		composer.New(),
		gomod.New(),
		gem.New(),
		npm.New(),
		javagradle.New(),
		javamaven.New(),
		nuget.New(),
		yarn.New(),
		pip.New(),
	)
}

// Manager ...
type Manager struct {
	Config  Config
	Plugin  models.IPlugin
	modules []models.Module
}

// Config ...
type Config struct {
	Path string
}

// New ...
func New(cfg Config) ([]*Manager, error) {
	var usePlugin models.IPlugin
	var managerSlice []*Manager
	for _, plugin := range registeredPlugins {
		if plugin.IsValid(cfg.Path) {
			if err := plugin.SetRootModule(cfg.Path); err != nil {
				return nil, err
			}

			usePlugin = plugin
			if usePlugin == nil {
				return nil, errNoPluginAvailable
			}

			managerSlice = append(managerSlice, &Manager{
				Config: cfg,
				Plugin: usePlugin,
			})
		}
	}

	return managerSlice, nil
}

// Run ...
func (m *Manager) Run() error {
	modulePath := m.Config.Path
	version, err := m.Plugin.GetVersion()
	if err != nil {
		return err
	}

	log.Infof("Current Language Version %s", version)
	if err := m.Plugin.HasModulesInstalled(modulePath); err != nil {
		return err
	}

	modules, err := m.Plugin.ListModulesWithDeps(modulePath)
	if err != nil {
		log.Error(err)
		return errFailedToReadModules
	}

	m.modules = modules

	return nil
}

// GetSource ...
func (m *Manager) GetSource() []models.Module {
	return m.modules
}
