// SPDX-License-Identifier: Apache-2.0
package common

import (
	"io"

	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/common"
	"github.com/spdx/tools-golang/tagvalue"
)

// WriteDocument serializes the document and writes it to the w writer
func WriteDocument(opts *options.Options, document common.AnyDocument, w io.Writer) error {
	var err error

	switch opts.Format {
	case options.OutputFormatSpdx:
		err = tagvalue.Write(document, w)
		if err != nil {
			return err
		}
	case options.OutputFormatJson:
		err = json.Write(document, w, json.EscapeHTML(true), json.Indent("\t"))
		if err != nil {
			return err
		}
	}

	return nil
}
