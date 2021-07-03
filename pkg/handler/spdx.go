// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"errors"
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/spdx/spdx-sbom-generator/pkg/format"
	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/spdx-sbom-generator/pkg/modules"
)

var errNoModuleManagerFound = errors.New("No module manager found")
var errOutputDirDoesNotExist = errors.New("Output Directory does not exist")

// SPDXSettings ...
type SPDXSettings struct {
	Version   string
	Path      string
	License   bool
	Depth     string
	OutputDir string
	Schema    string
	Format    string
}

type spdxHandler struct {
	config         SPDXSettings
	modulesManager []*modules.Manager
	format         format.Format
	outputFiles    map[string]string
	errors         map[string]error
}

// NewSPDX ...
func NewSPDX(settings SPDXSettings) (Handler, error) {
	if !helper.Exists(settings.OutputDir) {
		return nil, errOutputDirDoesNotExist
	}

	mm, err := modules.New(modules.Config{
		Path: settings.Path,
	})
	if err != nil {
		return nil, err
	}

	return &spdxHandler{
		config:         settings,
		modulesManager: mm,
		outputFiles:    map[string]string{},
		errors:         map[string]error{},
	}, err
}

// Run ...
func (sh *spdxHandler) Run() error {
	if len(sh.modulesManager) == 0 {
		return errNoModuleManagerFound
	}

	for _, mm := range sh.modulesManager {
		plugin := mm.Plugin.GetMetadata()
		filename := fmt.Sprintf("bom-%s.spdx", plugin.Slug)
		outputFile := filepath.Join(sh.config.OutputDir, filename)

		log.Infof("Running generator for Module Manager: `%s` with output `%s`", plugin.Slug, outputFile)
		if err := mm.Run(); err != nil {
			sh.errors[plugin.Slug] = err
			continue
		}

		format, err := format.New(format.Config{
			Filename:    outputFile,
			ToolVersion: sh.config.Version,
			GetSource: func() []models.Module {
				return mm.GetSource()
			},
		})
		if err != nil {
			sh.errors[plugin.Slug] = err
			continue
		}
		if err := format.Render(); err != nil {
			sh.errors[plugin.Slug] = err
			continue
		}
		sh.outputFiles[plugin.Slug] = outputFile
	}

	return nil
}

// Complete ...
func (sh *spdxHandler) Complete() error {
	if len(sh.errors) > 0 {
		log.Info("Command has completed with errors for some package managers, see details below")
		for plugin, err := range sh.errors {
			log.Infof("Plugin %s return error %v", plugin, err)
		}
	}

	if len(sh.outputFiles) > 0 {
		log.Info("Command completed successful for below package managers")
		for plugin, filepath := range sh.outputFiles {
			log.Infof("Plugin %s generated output at %s", plugin, filepath)
		}
	}
	return nil
}
