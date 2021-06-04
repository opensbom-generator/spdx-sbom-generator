// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"fmt"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"strings"
)

var httpReplacer = strings.NewReplacer("https://", "", "http://", "")

type GetPackageDetailsFunc = func(PackageName string) (string, error)

type MetadataDecoder struct {
	getPkgDetailsFunc GetPackageDetailsFunc
}

// New Metadata Decoder ...
func NewMetadataDecoder(pkgDetailsFunc GetPackageDetailsFunc) *MetadataDecoder {
	return &MetadataDecoder{
		getPkgDetailsFunc: pkgDetailsFunc,
	}
}

func SetMetadataValues(matadata *Metadata, datamap map[string]string) {
	matadata.Name = datamap[KeyName]
	matadata.Version = datamap[KeyVersion]
	matadata.Description = datamap[KeySummary]
	matadata.HomePage = httpReplacer.Replace(datamap[KeyHomePage])
	matadata.Author = datamap[KeyAuthor]
	matadata.AuthorEmail = datamap[KeyAuthorEmail]
	matadata.License = datamap[KeyLicense]
	matadata.Location = datamap[KeyLocation]

	// Parsing "Requires"
	if len(datamap[KeyRequires]) != 0 {
		matadata.Modules = strings.Split(datamap[KeyRequires], ",")
		for i, v := range matadata.Modules {
			matadata.Modules[i] = strings.TrimSpace(v)
		}
	}
}

func ParseMetadata(metadata *Metadata, packagedetails string) {
	pkgDataMap := make(map[string]string, 9)
	resultlines := strings.Split(packagedetails, "\n")

	for _, resline := range resultlines {
		res := strings.Split(resline, ":")
		if len(res) <= 1 {
			continue
		}
		value := strings.TrimSpace(res[1])
		// If there are more elements, then concatenate the second element onwards
		// with a ":" in between
		if len(res) > 2 {
			for i := 2; i < len(res); i++ {
				value += ":" + res[i]
			}
		}
		pkgDataMap[strings.ToLower(res[0])] = value
	}
	SetMetadataValues(metadata, pkgDataMap)
}

func (d *MetadataDecoder) BuildMetadata(packagename string) Metadata {
	var metadata Metadata

	metadatastr, err := d.getPkgDetailsFunc(packagename)
	if err != nil {
		// If there was error fetching package details, we are setting all members to NOASSERTION.
		// Except for Package Name
		SetMetadataToNoAssertion(&metadata, packagename)
	}
	ParseMetadata(&metadata, metadatastr)

	metadata.ProjectURL = BuildProjectUrl(metadata.Name, metadata.Version)
	metadata.PackageURL = BuildPackageUrl(metadata.Name, metadata.Version)
	if len(metadata.HomePage) > 0 {
		metadata.PackageURL = metadata.HomePage
	}
	metadata.PackageJsonURL = BuildPackageJsonUrl(metadata.Name, metadata.Version)

	metadata.DistInfoPath = BuildDistInfoPath(metadata.Location, metadata.Name, metadata.Version)
	metadata.LocalPath = BuildLocalPath(metadata.Location, metadata.Name)
	metadata.LicensePath = BuildLicenseUrl(metadata.Location, metadata.Name, metadata.Version)
	metadata.MetadataPath = BuildMetadataPath(metadata.Location, metadata.Name, metadata.Version)

	return metadata
}

func (d *MetadataDecoder) BuildModule(root bool, metadata Metadata) models.Module {
	var module models.Module
	module.Version = metadata.Version
	module.Name = metadata.Name
	module.Path = metadata.ProjectURL
	module.LocalPath = metadata.LocalPath

	contactType := models.Person
	if IsAuthorAnOrganization(metadata.Author, metadata.AuthorEmail) {
		contactType = models.Organization
	}

	// Prepare SupplierContact
	// Todo : How to determine if this is person or organization
	if len(metadata.AuthorEmail) > 0 {
		module.Supplier = models.SupplierContact{
			Type:  contactType,
			Name:  metadata.Author,
			Email: metadata.AuthorEmail,
		}
	}

	module.PackageURL = metadata.PackageURL

	// Todo : Get correct checksum
	module.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     GetCheckSum(metadata.Name),
	}

	licensePkg, err := helper.GetLicenses(metadata.DistInfoPath)
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
		if !helper.LicenseSPDXExists(licensePkg.ID) {
			licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
		}
	}
	module.PackageHomePage = metadata.HomePage
	module.OtherLicense = []*models.License{} // How to get this
	module.PackageComment = metadata.Description

	// Python CLI command lists all non-root packages.
	module.Root = root

	// Todo : Nee to build sub-module details
	module.Modules = map[string]*models.Module{}

	return module
}

func (d *MetadataDecoder) GetMetadataList(pkgs []Packages) (map[string]Metadata, []Metadata) {
	metainfo := map[string]Metadata{}
	metaList := []Metadata{}

	for _, pkg := range pkgs {
		metadata := d.BuildMetadata(pkg.Name)
		metaList = append(metaList, metadata)
		metainfo[strings.ToLower(pkg.Name)] = metadata
	}
	return metainfo, metaList
}

func (d *MetadataDecoder) ConvertMetadataToModules(isRoot bool, pkgs []Packages, modules *[]models.Module) map[string]Metadata {
	metainfo, metaList := d.GetMetadataList(pkgs)
	for _, metadata := range metaList {
		mod := d.BuildModule(isRoot, metadata)
		*modules = append(*modules, mod)
	}
	return metainfo
}

func BuildDependencyGraph(modules *[]models.Module, pkgsMetadata *map[string]Metadata) error {
	moduleMap := map[string]models.Module{}

	for _, module := range *modules {
		moduleMap[strings.ToLower(module.Name)] = module
	}

	for _, pkgmeta := range *pkgsMetadata {
		mod := moduleMap[strings.ToLower(pkgmeta.Name)]
		for _, modname := range pkgmeta.Modules {
			depModule := moduleMap[strings.ToLower(modname)]
			mod.Modules[depModule.Name] = &models.Module{
				Version:          depModule.Version,
				Name:             depModule.Name,
				Path:             depModule.Path,
				LocalPath:        depModule.LocalPath,
				Supplier:         depModule.Supplier,
				PackageURL:       depModule.PackageURL,
				CheckSum:         depModule.CheckSum,
				PackageHomePage:  depModule.PackageHomePage,
				LicenseConcluded: depModule.LicenseConcluded,
				LicenseDeclared:  depModule.LicenseDeclared,
				CommentsLicense:  depModule.CommentsLicense,
				OtherLicense:     depModule.OtherLicense,
				Copyright:        depModule.Copyright,
				PackageComment:   depModule.PackageComment,
				Root:             depModule.Root,
			}
		}
	}

	return nil
}
