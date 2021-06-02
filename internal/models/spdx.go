<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
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
	DependsOn               []Package
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
