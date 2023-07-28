// SPDX-License-Identifier: Apache-2.0
package v22

import (
	"errors"
	"fmt"
	"time"

	"github.com/opensbom-generator/parsers/meta"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/dochandlers/common"
	"github.com/spdx/spdx-sbom-generator/pkg/runner/options"
	spdxCommon "github.com/spdx/tools-golang/spdx/common"
	v2Common "github.com/spdx/tools-golang/spdx/v2/common"
	v22 "github.com/spdx/tools-golang/spdx/v2/v2_2"
)

const (
	spdxDocumentIdentifier = "DOCUMENT"
)

type Handler struct{}

func (h *Handler) CreateDocument(opts *options.Options, rootPackages []meta.Package) (spdxCommon.AnyDocument, error) {
	// fetch the top level package
	// TODO: what to do in case of multiple top level packages
	topLevelPkg := tov22Package(rootPackages[0])

	doc := &v22.Document{
		SPDXVersion:                v22.Version,
		DataLicense:                v22.DataLicense,
		SPDXIdentifier:             spdxDocumentIdentifier,
		DocumentName:               common.BuildName(topLevelPkg.PackageName, topLevelPkg.PackageVersion),
		DocumentNamespace:          common.BuildNamespace(topLevelPkg.PackageName, topLevelPkg.PackageVersion),
		ExternalDocumentReferences: nil,
		DocumentComment:            "",
		CreationInfo: &v22.CreationInfo{
			Creators: []v2Common.Creator{{
				Creator:     fmt.Sprintf("spdx-sbom-generator-%s", opts),
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
		rootPkgV22 := tov22Package(rootPkg)
		// relate the top-level package to document
		doc.Relationships = append(doc.Relationships, &v22.Relationship{
			RefA: v2Common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  doc.SPDXIdentifier,
				SpecialID:     "",
			},
			RefB: v2Common.DocElementID{
				DocumentRefID: "",
				ElementRefID:  rootPkgV22.PackageSPDXIdentifier,
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
	// type cast to v2.2 document
	v22Doc, ok := document.(*v22.Document)
	if !ok {
		return errors.New("error converting document")
	}

	/*
			iterate through each meta package
			convert each meta package to v2.2 package spec, and define a relationship
		    iterate through all sub packages and add them as relationships too
	*/
	for _, pkg := range metaPackages {
		v22Pkg := tov22Package(pkg)
		v22Doc.Packages = append(v22Doc.Packages, v22Pkg)

		// TODO: what happens to further nesting, if any?
		// traverse through sub packages of a meta package
		for _, subMod := range pkg.Packages {
			subV22Pkg := tov22Package(*subMod)

			v22Doc.Relationships = append(v22Doc.Relationships, &v22.Relationship{
				RefA: v2Common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  v22Pkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				RefB: v2Common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  subV22Pkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				Relationship:        "DEPENDS_ON",
				RelationshipComment: "",
			})
		}

		// append meta package licenses
		for licence := range pkg.OtherLicense {
			v22Doc.OtherLicenses = append(v22Doc.OtherLicenses, &v22.OtherLicense{
				LicenseIdentifier: pkg.OtherLicense[licence].ID,
				ExtractedText:     pkg.OtherLicense[licence].ExtractedText,
				LicenseName:       pkg.OtherLicense[licence].Name,
				LicenseComment:    pkg.OtherLicense[licence].Comments,
			})
		}

		v22Doc.Packages = append(v22Doc.Packages)
	}

	return nil
}

func tov22Package(p meta.Package) *v22.Package {
	return &v22.Package{
		PackageName:             p.Name,
		PackageSPDXIdentifier:   common.SetPkgSPDXIdentifier(p.Name, p.Version, p.Root),
		PackageVersion:          common.BuildVersion(p),
		PackageSupplier:         common.SetPkgValue(p.Supplier.Get()),
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
