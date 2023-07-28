// SPDX-License-Identifier: Apache-2.0
package runner

import (
	"errors"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/opensbom-generator/parsers/plugin"
	log "github.com/sirupsen/logrus"
	v23 "github.com/spdx/spdx-sbom-generator/pkg/runner/dochandlers/v23"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
)

type defaultGeneratorImplementation struct{}

func (di *defaultGeneratorImplementation) GetDocumentFormatHandler(opts *options.Options) (DocumentFormatHandler, error) {
	switch opts.SchemaVersion {
	case "2.3":
		return &v23.Handler{}, nil
	default:
		return nil, errors.New("no document format handler defined")
	}
}

func (di *defaultGeneratorImplementation) GetCodeParsers(opts *options.Options) ([]plugin.Plugin, error) {
	var parsers = make([]plugin.Plugin, 0)

	for _, p := range opts.Plugins {
		path := opts.Path
		if p.IsValid(path) {
			if err := p.SetRootModule(path); err != nil {
				return nil, err
			}
			parsers = append(parsers, p)
		}
	}

	return parsers, nil
}

func (di *defaultGeneratorImplementation) RunParser(opts *options.Options, plugin plugin.Plugin) ([]meta.Package, error) {
	modulePath := opts.Path
	version, err := plugin.GetVersion()
	if err != nil {
		return nil, err
	}

	if err = plugin.SetRootModule(opts.Path); err != nil {
		return nil, err
	}

	log.Infof("Current Language Version %s", version)
	log.Infof("Global Setting File %s", opts.GlobalSettingFile)
	if moduleErr := plugin.HasModulesInstalled(modulePath); moduleErr != nil {
		return nil, moduleErr
	}

	metaPackages, err := plugin.ListModulesWithDeps(modulePath, opts.GlobalSettingFile)
	if err != nil {
		return nil, err
	}

	return metaPackages, nil
}
