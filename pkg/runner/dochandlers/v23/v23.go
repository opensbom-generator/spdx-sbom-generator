// SPDX-License-Identifier: Apache-2.0

package v23

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
	"github.com/spdx/tools-golang/spdx"
)

type Handler struct{}

func (h *Handler) CreateDocument(opts *options.Options) (interface{}, error) {
	doc := &spdx.Document{
		SPDXVersion: spdx.Version,
		DataLicense: spdx.DataLicense,
		// ... this needs to be completed with all the required fuields
	}

	// TODO: Create top-level package
	// TODO: Relate top-level package to document

	return doc, nil
}

func (h *Handler) AddDocumentPackages(opts *options.Options, rawDoc interface{}, metaPackages []meta.Package) error {
	// The document gets fed as an empty interface, cast it:
	/*
		doc, ok := rawDoc.(*spdx.Document)
		if !ok {
			return errors.New("unable to cast the document object")
		}
	*/

	// TODO: Create the new SPDX packages
	// TODO: Assign the meta package data
	// TODO: Add to document
	// TODO: Relate the package to the top level directory

	// create new spdx.Packages and assign the data from the meta packages
	return nil
}

// WriteDocument serializes the document and writes it to the w writer
func (h *Handler) WriteDocument(opts *options.Options, rawDoc interface{}, w io.Writer) error {
	doc, ok := rawDoc.(*spdx.Document)
	if !ok {
		return errors.New("unable to cast the document object")
	}

	encoder := json.NewEncoder(w)
	encoder.SetIndent("", strings.Repeat(" ", opts.Indent))
	if err := encoder.Encode(doc); err != nil {
		return fmt.Errorf("encoding sbom to stream: %w", err)
	}
	return nil
}
