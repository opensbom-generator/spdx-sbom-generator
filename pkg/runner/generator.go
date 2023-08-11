// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/opensbom-generator/parsers/plugin"
	"github.com/pkg/errors"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/dochandlers/common"
	spdxCommon "github.com/spdx/tools-golang/spdx/common"

	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
)

type Generator struct {
	Options        options.Options
	implementation GeneratorImplementation
	docHandler     DocumentFormatHandler
}

type DocumentFormatHandler interface {
	CreateDocument(opts *options.Options, rootPackages []meta.Package) (spdxCommon.AnyDocument, error)
	AddDocumentPackages(opts *options.Options, doc spdxCommon.AnyDocument, metaPackages []meta.Package) error
}

type GeneratorImplementation interface {
	GetDocumentFormatHandler(*options.Options) (DocumentFormatHandler, error)
	GetCodeParsers(*options.Options) ([]plugin.Plugin, error)
	RunParser(*options.Options, plugin.Plugin) ([]meta.Package, error)
}

func New() *Generator {
	return NewWithOptions(options.Default)
}

func NewWithOptions(opts options.Options) *Generator {
	return &Generator{
		Options:        opts,
		implementation: &defaultGeneratorImplementation{},
		docHandler:     nil,
	}
}

// CreateSBOM is the main generator loop. It takes care of calling the
// underlying objects to get the language parsers, create the document
// and enrich it with the data read by the parsers.
//
// The main implementation is in the GeneratorImplementation. It implements
// the logic for the generator to do its job. All the format-specific
// parts are implemented in the DocumentFormatHandler.
//
// After running the language parsers on the source, the runner will use the
// selected document handler to create the SBOM and write it to the
// output writer.
func (g *Generator) CreateSBOM() error {
	// Reassign the document format handler again in case options
	// changed since the last run:
	newDocHandler, err := g.implementation.GetDocumentFormatHandler(&g.Options)
	if err != nil {
		return errors.Wrap(err, "error getting document format handler")
	}

	g.docHandler = newDocHandler

	// Check the codebase and return the applicable parsers
	parsers, err := g.implementation.GetCodeParsers(&g.Options)
	if err != nil {
		return errors.Wrap(err, "error getting applicable parsers")
	}

	var (
		metaPackages, rootPackages = make([]meta.Package, 0), make([]meta.Package, 0)
	)

	// Cycle all the applicable parsers and collect the dependency data
	for _, p := range parsers {
		// Each parser is passed to the runner implementation who takes
		// care of running it and returning the results
		parserPackages, err := g.implementation.RunParser(&g.Options, p)
		if err != nil {
			return errors.Wrap(err, "error running parser")
		}

		metaPackages = append(metaPackages, parserPackages...)
	}

	// cycle through all packages found and collect all top-level(root) packages
	for _, m := range metaPackages {
		if m.Root {
			rootPackages = append(rootPackages, m)
		}
	}

	// Get a new empty document from the document handler
	document, err := g.docHandler.CreateDocument(&g.Options, rootPackages)
	if err != nil {
		return fmt.Errorf("creating new document: %w", err)
	}

	// Pass the packages to the doc handler to create the packages. The document
	// handler knows how to turn the meta packages to native packages (ie SPDX 2.2/2.3)
	if err = g.docHandler.AddDocumentPackages(&g.Options, document, metaPackages); err != nil {
		return fmt.Errorf("adding dependency packages: %w", err)
	}

	// Ask the doc handler to write the rendered document to the io writer.
	if err = common.WriteDocument(&g.Options, document); err != nil {
		return fmt.Errorf("writing serialized document: %w", err)
	}

	return nil
}
