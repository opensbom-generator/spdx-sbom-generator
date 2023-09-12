// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"errors"
	"fmt"
	"path/filepath"

	log "github.com/sirupsen/logrus"

	"github.com/opensbom-generator/spdx-sbom-generator/pkg/format"
	"github.com/opensbom-generator/spdx-sbom-generator/pkg/helper"
	"github.com/opensbom-generator/spdx-sbom-generator/pkg/models"
	"github.com/opensbom-generator/spdx-sbom-generator/pkg/modules"
)

var errNoModuleManagerFound = errors.New("No module manager found")
var errOutputDirDoesNotExist = errors.New("Output Directory does not exist")

// SPDXSettings ...
type SPDXSettings struct {
	Version           string
	Path              string
	License           bool
	Depth             string
	OutputDir         string
	Schema            string
	Format            models.OutputFormat
	GlobalSettingFile string
}

type spdxHandler struct {
	config         SPDXSettings
	modulesManager []*modules.Manager
	format         format.Format
	outputFiles    map[string]string
	errors         map[string]error
}

// getFiletypeForOutputFormat gets the type suffix for the type of output chosen
func getFiletypeForOutputFormat(outputFormat models.OutputFormat) string {
	switch outputFormat {
	case models.OutputFormatSpdx:
		return "spdx" // nolint
	case models.OutputFormatJson:
		return "json"
	default:
		return "spdx"
	}
}

// NewSPDX ...
func NewSPDX(settings SPDXSettings) (Handler, error) {
	if !helper.Exists(settings.OutputDir) {
		return nil, errOutputDirDoesNotExist
	}

	mm, err := modules.New(modules.Config{
		Path:              settings.Path,
		GlobalSettingFile: settings.GlobalSettingFile,
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
		filename := fmt.Sprintf("bom-%s.%s", plugin.Slug, getFiletypeForOutputFormat(sh.config.Format))
		outputFile := filepath.Join(sh.config.OutputDir, filename)
		globalSettingFile := sh.config.GlobalSettingFile

		log.Infof("Running generator for Module Manager: `%s` with output `%s`", plugin.Slug, outputFile)
		if err := mm.Run(); err != nil {
			sh.errors[plugin.Slug] = err
			continue
		}

		format, err := format.New(format.Config{
			Filename:     outputFile,
			ToolVersion:  sh.config.Version,
			OutputFormat: sh.config.Format,
			GetSource: func() []models.Module {
				return mm.GetSource()
			},
			GlobalSettingFile: globalSettingFile,
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
