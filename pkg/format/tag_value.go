// SPDX-License-Identifier: Apache-2.0

package format

import (
	"bytes"
	"strings"
	"text/template"

	"github.com/opensbom-generator/spdx-sbom-generator/pkg/models"
)

// TagValueSPDXRenderer implements an SPDXRenderer that outputs JSON formatted SPDX documents
type TagValueSPDXRenderer struct{}

const tagValueTemplate = `SPDXVersion: {{ .SPDXVersion }}
DataLicense: {{ .DataLicense }}
SPDXID: {{ .SPDXID }}
DocumentName: {{ .DocumentName }}
DocumentNamespace: {{ .DocumentNamespace }}
Creator: {{ range .CreationInfo.Creators }}{{ . -}} {{ end }}
Created: {{ .CreationInfo.Created }}

{{ range .Packages }}
##### Package representing the {{.PackageName}}

PackageName: {{ .PackageName }}
SPDXID: {{ .SPDXID }}
{{ with .PackageVersion -}}
PackageVersion: {{ . }}
{{- end }}
PackageSupplier: {{ .PackageSupplier }}
PackageDownloadLocation: {{ .PackageDownloadLocation }}
FilesAnalyzed: {{ .FilesAnalyzed }}
{{- range .PackageChecksums }}
PackageChecksum: {{ .Algorithm }}: {{ .Value }}
{{- end }}
PackageHomePage: {{ .PackageHomePage }}
PackageLicenseConcluded: {{ .PackageLicenseConcluded }}
PackageLicenseDeclared: {{ .PackageLicenseDeclared }}
PackageCopyrightText: {{ .PackageCopyrightText }}
PackageLicenseComments: {{ .PackageLicenseComments }}
PackageComment: {{ .PackageComment }}
{{ end }}
{{- range .Relationships }}
Relationship: {{ .SPDXElementID }} {{ .RelationshipType }} {{ .RelatedSPDXElement }}
{{- end }}

{{- with .ExtractedLicensingInfos -}}
##### Non-standard license
{{ range . }}
LicenseID: {{ .LicenseID }}
ExtractedText: {{ .ExtractedText }}
LicenseName: {{ .LicenseName }}
LicenseComment: {{ .LicenseComment }}
{{- end -}}
{{- end -}}`

// RenderDocument uses golang templates to generated an SPDX tag value format output
func (t TagValueSPDXRenderer) RenderDocument(document models.Document) ([]byte, error) {
	tmpl := template.New("tagValue")
	tmpl, err := tmpl.Funcs(template.FuncMap{
		"isAsserted": func(s string) bool {
			return !strings.Contains(s, noAssertion)
		},
	}).Parse(tagValueTemplate)

	if err != nil {
		return nil, err
	}
	templateBuffer := new(bytes.Buffer)
	err = tmpl.Execute(templateBuffer, document)
	if err != nil {
		return nil, err
	}
	return templateBuffer.Bytes(), err
}
