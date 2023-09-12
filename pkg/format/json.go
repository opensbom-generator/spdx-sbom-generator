// SPDX-License-Identifier: Apache-2.0

package format

import (
	"encoding/json"

	"github.com/opensbom-generator/spdx-sbom-generator/pkg/models"
)

// JsonSPDXRenderer implements an SPDXRenderer that outputs JSON formatted SPDX documents
type JsonSPDXRenderer struct{}

// RenderDocument uses golang JSON utilities to generated an indented output
func (j JsonSPDXRenderer) RenderDocument(document models.Document) ([]byte, error) {
	jsonBytes, err := json.MarshalIndent(document, "", "\t")
	if err != nil {
		return nil, err
	}
	return jsonBytes, err
}
