// SPDX-License-Identifier: Apache-2.0

package models

// Package
// JSON tags annotated from official example (https://github.com/spdx/spdx-spec/blob/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json)
// and official schema (https://github.com/spdx/spdx-spec/blob/v2.2.2/schemas/spdx-schema.json)
type Package struct {
	PackageName             string            `json:"name,omitempty"`
	SPDXID                  string            `json:"SPDXID,omitempty"`
	PackageVersion          string            `json:"versionInfo,omitempty"`
	PackageSupplier         string            `json:"supplier,omitempty"`
	PackageDownloadLocation string            `json:"downloadLocation,omitempty"`
	FilesAnalyzed           bool              `json:"filesAnalyzed"`
	PackageChecksums        []PackageChecksum `json:"checksums"`
	PackageHomePage         string            `json:"homepage,omitempty"`
	PackageLicenseConcluded string            `json:"licenseConcluded,omitempty"`
	PackageLicenseDeclared  string            `json:"licenseDeclared,omitempty"`
	PackageCopyrightText    string            `json:"copyrightText,omitempty"`
	PackageLicenseComments  string            `json:"licenseComments,omitempty"`
	PackageComment          string            `json:"comment,omitempty"`
	RootPackage             bool              `json:"-"`
}

// Document
// JSON tags annotated from official example (https://github.com/spdx/spdx-spec/blob/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json)
// and official schema (https://github.com/spdx/spdx-spec/blob/v2.2.2/schemas/spdx-schema.json
type Document struct {
	SPDXVersion             string                   `json:"spdxVersion,omitempty"`
	DataLicense             string                   `json:"dataLicense,omitempty"`
	SPDXID                  string                   `json:"SPDXID,omitempty"`
	DocumentName            string                   `json:"name,omitempty"`
	DocumentNamespace       string                   `json:"documentNamespace,omitempty"`
	CreationInfo            CreationInfo             `json:"creationInfo,omitempty"`
	Packages                []Package                `json:"packages,omitempty"`
	Relationships           []Relationship           `json:"relationships,omitempty"`
	ExtractedLicensingInfos []ExtractedLicensingInfo `json:"hasExtractedLicensingInfos,omitempty"`
}

// CreationInfo
// JSON tags annotated from official example (https://github.com/spdx/spdx-spec/blob/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json)
// and official schema (https://github.com/spdx/spdx-spec/blob/v2.2.2/schemas/spdx-schema.json
type CreationInfo struct {
	Comment            string   `json:"comment,omitempty"`
	Created            string   `json:"created,omitempty"`
	Creators           []string `json:"creators,omitempty"`
	LicenceListVersion string   `json:"licenseListVersion,omitempty"`
}

// Relationship
// JSON tags annotated from official example (https://github.com/spdx/spdx-spec/blob/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json)
// and official schema (https://github.com/spdx/spdx-spec/blob/v2.2.2/schemas/spdx-schema.json
type Relationship struct {
	SPDXElementID      string `json:"spdxElementId,omitempty"`
	RelatedSPDXElement string `json:"relatedSpdxElement,omitempty"`
	RelationshipType   string `json:"relationshipType,omitempty"`
}

// ExtractedLicensingInfo
// JSON tags annotated from official example (https://github.com/spdx/spdx-spec/blob/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json)
// and official schema (https://github.com/spdx/spdx-spec/blob/v2.2.2/schemas/spdx-schema.json
type ExtractedLicensingInfo struct {
	LicenseID      string `json:"licenseId,omitempty"`
	ExtractedText  string `json:"extractedText,omitempty"`
	LicenseName    string `json:"name,omitempty"`
	LicenseComment string `json:"comment,omitempty"`
}

// PackageChecksum
// JSON tags annotated from official example (https://github.com/spdx/spdx-spec/blob/v2.2.2/examples/SPDXJSONExample-v2.2.spdx.json)
// and official schema (https://github.com/spdx/spdx-spec/blob/v2.2.2/schemas/spdx-schema.json
type PackageChecksum struct {
	Algorithm HashAlgorithm `json:"algorithm"`
	Value     string        `json:"checksumValue"`
}
