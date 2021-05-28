// SPDX-License-Identifier: Apache-2.0

package handler

import (
	log "github.com/sirupsen/logrus"

	"spdx-sbom-generator/internal/format"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/modules"
)

// SPDXSettings ...
type SPDXSettings struct {
	Version string
	Path    string
	License bool
	Depth   string
	Output  string
	Schema  string
}

type spdxHandler struct {
	config         SPDXSettings
	modulesManager *modules.Manager
	format         format.Format
}

// NewSPDX ...
func NewSPDX(settings SPDXSettings) (Handler, error) {
	mm, err := modules.New(modules.Config{
		Path: settings.Path,
	})
	if err != nil {
		return nil, err
	}

	format, err := format.New(format.Config{
		Filename: settings.Output,
		GetSource: func() []models.Module {
			return mm.GetSource()
		},
	})
	if err != nil {
		return nil, err
	}

	return &spdxHandler{
		config:         settings,
		modulesManager: mm,
		format:         format,
	}, err
}

// Run ...
func (sh *spdxHandler) Run() error {
	plugin := sh.modulesManager.Plugin.GetMetadata()
	log.Infof("Running generator for Module Manager: `%s` with output `%s`", plugin.Slug, sh.config.Output)
	if err := sh.modulesManager.Run(); err != nil {
		return err
	}

	if err := sh.format.Render(); err != nil {
		return err
	}

	return nil
}

// Complete ...
func (sh *spdxHandler) Complete() error {
	log.Info("Command has completed, below cli stats ")
	return nil
}
