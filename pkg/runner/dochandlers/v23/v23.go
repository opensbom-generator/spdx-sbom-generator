// SPDX-License-Identifier: Apache-2.0
package v23

import (
	"errors"
	"fmt"
	"time"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/dochandlers/common"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
	spdxCommon "github.com/spdx/tools-golang/spdx/common"
	v2Common "github.com/spdx/tools-golang/spdx/v2/common"
	v23 "github.com/spdx/tools-golang/spdx/v2/v2_3"
)

const (
	spdxDocumentIdentifier = "DOCUMENT"
)

type Handler struct{}

func (h *Handler) CreateDocument(opts *options.Options, rootPackages []meta.Package) (spdxCommon.AnyDocument, error) {
	// fetch the top level package
	// TODO: what to do in case of multiple top level packages
	topLevelPkg := tov23Package(rootPackages[0])

	doc := &v23.Document{
		SPDXVersion:                v23.Version,
		DataLicense:                v23.DataLicense,
		SPDXIdentifier:             spdxDocumentIdentifier,
		DocumentName:               common.BuildName(topLevelPkg.PackageName, topLevelPkg.PackageVersion),
		DocumentNamespace:          common.BuildNamespace(topLevelPkg.PackageName, topLevelPkg.PackageVersion),
		ExternalDocumentReferences: nil,
		DocumentComment:            "",
		CreationInfo: &v23.CreationInfo{
			Creators: []v2Common.Creator{{
				Creator:     fmt.Sprintf("spdx-sbom-generator-%s", opts.Version),
				CreatorType: "Tool",
			}},
			Created: time.Now().UTC().Format(time.RFC3339),
		},
		Packages:      nil,
		Files:         nil,
		OtherLicenses: nil,
		Relationships: nil,
		Annotations:   nil,
		Snippets:      nil,
		Reviews:       nil,
	}

	for _, rootPkg := range rootPackages {
		rootPkgV23 := tov23Package(rootPkg)
		// relate the top-level package to document
		doc.Relationships = append(doc.Relationships, &v23.Relationship{
			RefA: v2Common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  doc.SPDXIdentifier,
				SpecialID:     "",
			},
			RefB: v2Common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  rootPkgV23.PackageSPDXIdentifier,
				SpecialID:     "",
			},
			Relationship:        "DESCRIBES",
			RelationshipComment: "",
		})
	}

	return doc, nil
}

func (h *Handler) AddDocumentPackages(opts *options.Options, document spdxCommon.AnyDocument, metaPackages []meta.Package) error {
	// TODO: https://github.com/spdx/tools-golang/blob/main/convert/chain.go#L38 use for conversion?
	// type cast to v2.3 document
	v23Doc, ok := document.(*v23.Document)
	if !ok {
		return errors.New("error converting document")
	}

	/*
			iterate through each meta package
			convert each meta package to v2.3 package spec, and define a relationship
		    iterate through all sub packages and add them as relationships too
	*/
	for _, pkg := range metaPackages {
		v23Pkg := tov23Package(pkg)

		// TODO: what happens to further nesting, if any?
		// traverse through sub packages of a meta package
		for _, subMod := range pkg.Packages {
			subV23Pkg := tov23Package(*subMod)

			v23Doc.Relationships = append(v23Doc.Relationships, &v23.Relationship{
				RefA: v2Common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  v23Pkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				RefB: v2Common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  subV23Pkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				Relationship:        "DEPENDS_ON",
				RelationshipComment: "",
			})
		}

		// append meta package licenses
		for licence := range pkg.OtherLicense {
			v23Doc.OtherLicenses = append(v23Doc.OtherLicenses, &v23.OtherLicense{
				LicenseIdentifier: pkg.OtherLicense[licence].ID,
				ExtractedText:     pkg.OtherLicense[licence].ExtractedText,
				LicenseName:       pkg.OtherLicense[licence].Name,
				LicenseComment:    pkg.OtherLicense[licence].Comments,
			})
		}
		v23Doc.Packages = append(v23Doc.Packages, v23Pkg)
	}

	return nil
}

func tov23Package(p meta.Package) *v23.Package {
	return &v23.Package{
		PackageName:           p.Name,
		PackageSPDXIdentifier: common.SetPkgSPDXIdentifier(p.Name, p.Version, p.Root),
		PackageVersion:        common.BuildVersion(p),
		PackageSupplier: &v2Common.Supplier{
			Supplier:     p.Supplier.Name,
			SupplierType: string(p.Supplier.Type),
		},
		PackageDownloadLocation: p.PackageDownloadLocation,
		FilesAnalyzed:           false,
		PackageChecksums: []v2Common.Checksum{{
			Algorithm: v2Common.ChecksumAlgorithm(p.Checksum.Algorithm),
			Value:     p.Checksum.String(),
		}},
		PackageHomePage:         common.BuildHomepageURL(p.PackageURL),
		PackageLicenseConcluded: common.NoAssertion,
		PackageLicenseDeclared:  common.NoAssertion,
		PackageCopyrightText:    common.NoAssertion,
		PackageLicenseComments:  p.CommentsLicense,
		PackageComment:          p.PackageComment,
		IsUnpackaged:            p.Root,
	}
}
