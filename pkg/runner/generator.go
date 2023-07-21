// SPDX-License-Identifier: Apache-2.0

package runner

import (
	"fmt"
	"io"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/opensbom-generator/parsers/plugin"

	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
)

type Generator struct {
	Options        options.Options
	implementation GeneratorImplementation
	docHandler     DocumentFormatHandler
}

type DocumentFormatHandler interface {
	CreateDocument(*options.Options) (interface{}, error)
	AddDocumentPackages(*options.Options, interface{}, []meta.Package) error
	WriteDocument(*options.Options, interface{}, io.Writer) error
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
// underlying objects to get the languaga parsers, create the document
// and enrich it with the data read by the parsers.
//
// The main implementation is in the GeneratorImplementation. It implements
// the logic for the generator to do its job. All the format-specific
// parts are implemented in the DocumentFormatHandler.
//
// After running the language parsers on the source, the runner will use the
// selected document handler to create the SBOM and write it to the
// output writer.
func (g *Generator) CreateSBOM(path string, output io.Writer) error {
	// Reassign the document format handler again in case options
	// changed since the last run:
	newDocHandler, err := g.implementation.GetDocumentFormatHandler(&g.Options)
	if err != nil {
		return fmt.Errorf("getting document format handler: %w", err)
	}

	g.docHandler = newDocHandler

	// Check the codebase and return the applicable parsers
	parsers, err := g.implementation.GetCodeParsers(&g.Options)
	if err != nil {
		return fmt.Errorf("getting applicable parsers: %w", err)
	}

	// Get a new empty document from the document handler:
	document, err := g.docHandler.CreateDocument(&g.Options)
	if err != nil {
		return fmt.Errorf("creating new document: %w", err)
	}

	// Cycle all the applicable parsers and collect the dependency data
	metaPackages := []meta.Package{}
	for _, p := range parsers {
		// Each parser is passed to the runner implementation who takes
		// care of running it and retguring the results:
		parserPackages, err := g.implementation.RunParser(&g.Options, p)
		if err != nil {
			return fmt.Errorf("running parser: %w", err)
		}

		metaPackages = append(metaPackages, parserPackages...)
	}

	// Pass the packages to the dochandler to create the packages. The document
	// handler knows how to turn the metapackages to natice (ie SPDX 2.2/2.3) packages
	if err := g.docHandler.AddDocumentPackages(&g.Options, document, metaPackages); err != nil {
		return fmt.Errorf("adding dependency packages: %w", err)
	}

	// Ask the doc handler to write the rendered document to the io writer.
	if err := g.docHandler.WriteDocument(&g.Options, document, output); err != nil {
		return fmt.Errorf("writing serialized document: %w", err)
	}

	return nil
}
