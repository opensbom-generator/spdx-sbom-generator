package models

// Package ...
type Package struct {
	PackageName             string
	SPDXID                  string
	PackageVersion          string
	PackageSupplier         string
	PackageDownloadLocation string
	FilesAnalyzed           bool
	PackageChecksum         string
	PackageHomePage         string
	PackageLicenseConcluded string
	PackageLicenseDeclared  string
	PackageCopyrightText    string
	PackageLicenseComments  string
	PackageComment          string
	RootPackage             bool
	Packages                []Package
}

// Document ...
type Document struct {
	SPDXVersion       string
	DataLicense       string
	SPDXID            string
	DocumentName      string
	DocumentNamespace string
	Creator           string
	Created           string
}
