<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
package modules

import (
	"errors"
<<<<<<< HEAD
	"spdx-sbom-generator/internal/modules/composer"
	"spdx-sbom-generator/internal/modules/yarn"
=======
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb

	log "github.com/sirupsen/logrus"

	"spdx-sbom-generator/internal/models"
<<<<<<< HEAD
=======
	"spdx-sbom-generator/internal/modules/composer"
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
	"spdx-sbom-generator/internal/modules/gomod"
	"spdx-sbom-generator/internal/modules/npm"
)

var (
	errNoPluginAvailable   = errors.New("no plugin system available for current path")
	errNoModulesInstalled  = errors.New("there are no components in the BOM. The project may not contain dependencies, please install modules")
	errFailedToReadModules = errors.New("failed to read modules")
)

var registeredPlugins []models.IPlugin

func init() {
	registeredPlugins = append(registeredPlugins,
<<<<<<< HEAD
		gomod.New(),
		npm.New(),
		composer.New(),
		yarn.New(),
=======
		composer.New(),
		gomod.New(),
		npm.New(),
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
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
func New(cfg Config) (*Manager, error) {
	var usePlugin models.IPlugin
	for _, plugin := range registeredPlugins {
		if plugin.IsValid(cfg.Path) {
			if err := plugin.SetRootModule(cfg.Path); err != nil {
				return nil, err
			}
			usePlugin = plugin
			break
		}
	}

	if usePlugin == nil {
		return nil, errNoPluginAvailable
	}

	return &Manager{
		Config: cfg,
		Plugin: usePlugin,
	}, nil
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
