// SPDX-License-Identifier: Apache-2.0
package runner

import (
	"errors"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/opensbom-generator/parsers/plugin"
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

func (di *defaultGeneratorImplementation) GetCodeParsers(*options.Options) ([]plugin.Plugin, error) {
	return nil, nil
}

func (di *defaultGeneratorImplementation) RunParser(*options.Options, plugin.Plugin) ([]meta.Package, error) {
	return nil, nil
}
