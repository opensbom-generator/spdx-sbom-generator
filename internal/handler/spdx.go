// SPDX-License-Identifier: Apache-2.0

package handler

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/gookit/color"
	"github.com/i582/cfmt/cmd/cfmt"

	"spdx-sbom-generator/internal/format"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"spdx-sbom-generator/internal/modules"
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

	reportError := func(pluginName string) {
		cfmt.Println(cfmt.Sprintf("{{Could not build SBOM for Package Manager: }}::red|bold`%s`", color.White.Sprintf(pluginName)))
	}

	cfmt.Println()
	cfmt.Println(cfmt.Sprintf("{{Searching for Package Managers ... }}::cyan|bold"))
	for _, mm := range sh.modulesManager {
		plugin := mm.Plugin.GetMetadata()
		filename := fmt.Sprintf("bom-%s.spdx", plugin.Slug)
		outputFile := filepath.Join(sh.config.OutputDir, filename)

		cfmt.Println()
		cfmt.Println(cfmt.Sprintf("{{Module Manager Detected: }}::cyan|bold`%s`", color.Yellow.Sprintf(plugin.Slug)))
		cfmt.Println(cfmt.Sprintf("{{Output file will be at: }}::cyan|bold`%s`", color.Yellow.Sprintf(outputFile)))
		if err := mm.Run(); err != nil {
			sh.errors[plugin.Slug] = err
			reportError(plugin.Slug)
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
			reportError(plugin.Slug)
			continue
		}
		if err := format.Render(); err != nil {
			sh.errors[plugin.Slug] = err
			reportError(plugin.Slug)
			continue
		}
		sh.outputFiles[plugin.Slug] = outputFile
	}

	return nil
}

// Complete ...
func (sh *spdxHandler) Complete() error {
	cfmt.Println()
	cfmt.Printf("{{                 Command has completed, below cli stats                      }}::bgBlue|#ffffff")
	cfmt.Println()
	cfmt.Println("PACKAGE MANAGER          | OUTPUT PATH                              | STATUS")
	cfmt.Println("-------------------------| ---------------------------------------- | ------")

	if len(sh.outputFiles) > 0 {
		for plugin, filepath := range sh.outputFiles {
			cfmt.Println(cfmt.Sprintf("%-15s          {{|}}::white|bold %-30s           {{|}}::white|bold %s", helper.DecorateResult(plugin, 15), helper.DecorateResult(filepath, 30), color.BgGreen.Sprintf("COMPLETED")))
		}
	}

	if len(sh.errors) > 0 {
		for plugin, err := range sh.errors {
			cfmt.Println(cfmt.Sprintf("%-15s          {{|}}::white|bold %-30s           {{|}}::white|bold %s", helper.DecorateResult(plugin, 15), helper.DecorateResult("ERROR, output not generated", 30), color.BgRed.Sprintf(err.Error())))
		}
	}
	cfmt.Println("-------------------------| ---------------------------------------- | ------")
	return nil
}
