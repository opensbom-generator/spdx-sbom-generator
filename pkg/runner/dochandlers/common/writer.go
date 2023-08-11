// SPDX-License-Identifier: Apache-2.0
package common

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"

	"github.com/pkg/errors"
	log "github.com/sirupsen/logrus"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/common"
	"github.com/spdx/tools-golang/tagvalue"
)

// WriteDocument serializes the document and writes it to the w writer
func WriteDocument(opts *options.Options, document common.AnyDocument) error {
	var err error
	var f *os.File

	// if an output directory is specified then write to file in that directory else write to stdout
	if opts.OutputDir != "" {
		filename := fmt.Sprintf("bom-%s.%s", opts.Slug, opts.Format.String())
		outputFile := filepath.Join(opts.OutputDir, filename)
		f, err = os.OpenFile(outputFile, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return errors.Wrap(err, "error opening file")
		}
	} else {
		f = os.Stdout
	}

	w := bufio.NewWriter(f)

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

	err = w.Flush()
	if err != nil {
		return errors.Wrap(err, "error writing file")
	}

	log.Infof("SBOM written to %s", f.Name())
	return nil
}
