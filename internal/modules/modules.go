package modules

import (
	"errors"

	log "github.com/sirupsen/logrus"

	"spdx-sbom-generator/internal/models"
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
		gomod.New(),
		npm.New(),
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

	modules, err := m.Plugin.ListAllModules(modulePath)
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
