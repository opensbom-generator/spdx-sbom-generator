// SPDX-License-Identifier: Apache-2.0
package runner

import (
	"github.com/opensbom-generator/parsers/meta"
	"github.com/opensbom-generator/parsers/plugin"
	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	v22 "github.com/spdx/spdx-sbom-generator/pkg/runner/dochandlers/v22"
	v23 "github.com/spdx/spdx-sbom-generator/pkg/runner/dochandlers/v23"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
)

type defaultGeneratorImplementation struct{}

// GetDocumentFormatHandler gets a document handler according to the spdx schema version
func (di *defaultGeneratorImplementation) GetDocumentFormatHandler(opts *options.Options) (DocumentFormatHandler, error) {
	switch opts.SchemaVersion {
	case "2.3":
		return &v23.Handler{}, nil
	case "2.2":
		return &v22.Handler{}, nil
	default:
		return nil, errors.New("no document format handler defined")
	}
}

// GetCodeParsers gets all valid parsers for the project path.
// In case of multiple programming languages in the project, multiple parsers are returned.
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

// RunParser runs the parser to parse packages from the project
// The parsers are implemented at https://github.com/opensbom-generator/parsers
func (di *defaultGeneratorImplementation) RunParser(opts *options.Options, plugin plugin.Plugin) ([]meta.Package, error) {
	modulePath := opts.Path
	version, err := plugin.GetVersion()
	if err != nil {
		return nil, err
	}

	if err = plugin.SetRootModule(opts.Path); err != nil {
		return nil, err
	}

	// setting slug which is used later when generating SBOM
	opts.SetSlug(plugin.GetMetadata().Slug)

	log.Infof("Current Language Version %s", version)
	log.Infof("Global Setting File path %s", opts.GlobalSettingFile)
	log.Infof("Parsing %s for packages", opts.Path)

	if moduleErr := plugin.HasModulesInstalled(modulePath); moduleErr != nil {
		return nil, moduleErr
	}

	metaPackages, err := plugin.ListModulesWithDeps(modulePath, opts.GlobalSettingFile)
	if err != nil {
		return nil, errors.Wrap(err, "error parsing packages")
	}

	return metaPackages, nil
}
