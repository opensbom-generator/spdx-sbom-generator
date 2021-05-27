package format

import (
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"spdx-sbom-generator/internal/models"
)

const (
	RFC3339 = "2006-01-02T15:04:05Z"
)

// Format ...
type Format struct {
	Config Config
}

// Config ...
type Config struct {
	Filename  string
	GetSource func() []models.Module
}

// New ...
func New(cfg Config) (Format, error) {
	return Format{
		Config: cfg,
	}, nil
}

// Build ...
func (f *Format) Render() error {
	modules := f.Config.GetSource()
	document, err := buildDocument(modules[0])
	if err != nil {
		return err
	}

	packages, otherLicenses, err := buildPackages(modules)
	if err != nil {
		return err
	}

	file, err2 := os.Create(f.Config.Filename)
	if err2 != nil {
		return err2
	}

	// todo organize file generation code below
	//Print DOCUMENT
	file.WriteString(fmt.Sprintf("SPDXVersion: %s\n", document.SPDXVersion))
	file.WriteString(fmt.Sprintf("DataLicense: %s\n", document.DataLicense))
	file.WriteString(fmt.Sprintf("SPDXID: %s\n", document.SPDXID))
	file.WriteString(fmt.Sprintf("DocumentName: %s\n", document.DocumentName))
	file.WriteString(fmt.Sprintf("DocumentNamespace: %s\n", document.DocumentNamespace))
	file.WriteString(fmt.Sprintf("Creator: %s\n", document.Creator))
	file.WriteString(fmt.Sprintf("Created: %v\n\n", document.Created))

	//Print Package
	rootPackageSPDXID := fmt.Sprintf("SPDXRef-Package-%s", document.DocumentName)
	for _, pkg := range packages {
		file.WriteString(fmt.Sprintf("##### Package representing the %s\n\n", pkg.PackageName))
		generatePackage(file, pkg)
		if pkg.RootPackage {
			file.WriteString(fmt.Sprintf("Relationship %s DESCRIBES %s \n\n", document.SPDXID, pkg.SPDXID))
		} else {
			file.WriteString(fmt.Sprintf("Relationship %s CONTAINS %s \n\n", rootPackageSPDXID, pkg.SPDXID))
		}
		if len(pkg.Packages) > 0 {
			file.WriteString(fmt.Sprintf("##### Package representing the %s\n\n", pkg.PackageName))
			for _, subPkg := range packages {
				generatePackage(file, pkg)
				file.WriteString(fmt.Sprintf("Relationship %s CONTAINS %s \n\n", pkg.PackageName, subPkg.PackageName))
			}
		}
	}

	//Print Other Licenses
	if len(otherLicenses) > 0 {
		file.WriteString("##### Non-standard license\n\n")
		for lic := range otherLicenses {
			file.WriteString(fmt.Sprintf("LicenseID: %s\n", lic))
			file.WriteString(fmt.Sprintf("LicenseName: %s\n", otherLicenses[lic].Name))
			file.WriteString(fmt.Sprintf("LicenseText: %s\n", otherLicenses[lic].ExtractedText))
			file.WriteString(fmt.Sprintf("LicenseComment: %s\n\n", otherLicenses[lic].Comments))
		}
	}

	// Write to file
	file.Sync()

	return nil
}

func generatePackage(file *os.File, pkg models.Package) {
	file.WriteString(fmt.Sprintf("PackageName: %s\n", pkg.PackageName))
	file.WriteString(fmt.Sprintf("SPDXID: %s\n", pkg.SPDXID))
	file.WriteString(fmt.Sprintf("PackageVersion: %s\n", pkg.PackageVersion))
	file.WriteString(fmt.Sprintf("PackageSupplier: %s\n", pkg.PackageSupplier))
	file.WriteString(fmt.Sprintf("PackageDownloadLocation: %s\n", pkg.PackageDownloadLocation))
	file.WriteString(fmt.Sprintf("FilesAnalyzed: %v\n", pkg.FilesAnalyzed))
	file.WriteString(fmt.Sprintf("PackageChecksum: %v\n", pkg.PackageChecksum))
	file.WriteString(fmt.Sprintf("PackageHomePage: %v\n", pkg.PackageHomePage))
	file.WriteString(fmt.Sprintf("PackageLicenseConcluded: %v\n", pkg.PackageLicenseConcluded))
	file.WriteString(fmt.Sprintf("PackageLicenseDeclared: %v\n", pkg.PackageLicenseDeclared))
	file.WriteString(fmt.Sprintf("PackageCopyrightText: %v\n", pkg.PackageCopyrightText))
	file.WriteString(fmt.Sprintf("PackageLicenseComments: %v\n", pkg.PackageLicenseComments))
	file.WriteString(fmt.Sprintf("PackageComment: %v\n\n", pkg.PackageComment))
}

func buildDocument(module models.Module) (*models.Document, error) {
	uuid := uuid.New().String()
	t := time.Now()
	created := t.Format(RFC3339)
	return &models.Document{
		SPDXVersion:       "SPDX-2.2",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      module.Name,
		DocumentNamespace: fmt.Sprintf("http://spdx.org/spdxpackages/%s-%s-%s", module.Name, module.Version, uuid),
		Creator:           "Tool: spdx-sbom-generator-XXXXX",
		Created:           created,
	}, nil
}

// WIP
func buildPackages(modules []models.Module) ([]models.Package, map[string]*models.License, error) {
	packages := make([]models.Package, len(modules))
	otherLicenses := map[string]*models.License{}
	for i, module := range modules {
		pkg, err := convertToPackage(module)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert module %w", err)
		}
		subPackages := make([]models.Package, len(module.Modules))
		idx := 0
		for _, subMod := range module.Modules {
			subPkg, err := convertToPackage(*subMod)
			if err != nil {
				return nil, nil, err
			}
			subPackages[idx] = subPkg
			idx++
		}
		pkg.Packages = subPackages
		for l := range module.OtherLicense {
			otherLicenses[module.OtherLicense[l].ID] = module.OtherLicense[l]
		}
		packages[i] = pkg
	}

	return packages, otherLicenses, nil
}

// WIP
func convertToPackage(module models.Module) (models.Package, error) {
	setPkgValue := func(s string) string {
		if s == "" {
			return "NOASSERTION"
		}

		return s
	}
	return models.Package{
		PackageName:             module.Name,
		SPDXID:                  fmt.Sprintf("SPDXRef-Package-%s", module.Name),
		PackageVersion:          module.Version,
		PackageSupplier:         "NOASSERTION",
		PackageDownloadLocation: module.PackageURL,
		FilesAnalyzed:           false,
		PackageChecksum:         module.CheckSum.String(),
		PackageHomePage:         module.PackageURL,
		PackageLicenseConcluded: setPkgValue(module.LicenseConcluded),
		PackageLicenseDeclared:  setPkgValue(module.LicenseDeclared),
		PackageCopyrightText:    setPkgValue(""),
		PackageLicenseComments:  setPkgValue(""),
		PackageComment:          setPkgValue(""),
		RootPackage:             module.Root,
	}, nil
}
