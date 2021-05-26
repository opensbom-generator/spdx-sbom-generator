package format

import (
	"encoding/json"
	"fmt"
	"os"
	"time"

	"github.com/google/uuid"

	"spdx-sbom-generator/internal/models"
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
	// Remove
	println("Modules formatter")
	a, _ := json.MarshalIndent(modules, " ", "\t")
	fmt.Println(string(a))
	document, err := buildDocument(modules[0])
	if err != nil {
		return err
	}

	packages, err := buildPackages(modules)
	if err != nil {
		return err
	}

	// THIS IS JUST TESTING DATA IN JSON FORMAT
	println(f.Config.Filename)
	file, err2 := os.Create(f.Config.Filename)
	if err2 != nil {
		return err2
	}
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

	// Write to file
	file.Sync()

	return nil
}

func generatePackage(file *os.File, pkg models.Package) {
	file.WriteString(fmt.Sprintf("PackageNam: %s\n", pkg.PackageName))
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
	return &models.Document{
		SPDXVersion:       "SPDX-2.2",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      module.Name,
		DocumentNamespace: fmt.Sprintf("http://spdx.org/spdxpackages/%s-%s-%s", module.Name, module.Version, uuid),
		Creator:           "Tool: spdx-sbom-generator-XXXXX",
		Created:           time.Now(),
	}, nil
}

// WIP
func buildPackages(modules []models.Module) ([]models.Package, error) {
	packages := make([]models.Package, len(modules))
	for i, module := range modules {
		pkg, err := convertToPackage(module)
		if err != nil {
			return nil, fmt.Errorf("failed to convert module %w", err)
		}
		subPackages := make([]models.Package, len(module.Modules))
		idx := 0
		for _, subMod := range module.Modules {
			subPkg, err := convertToPackage(*subMod)
			if err != nil {
				return nil, err
			}
			subPackages[idx] = subPkg
			idx++
		}
		pkg.Packages = subPackages
		packages[i] = pkg
	}

	return packages, nil
}

// WIP
func convertToPackage(module models.Module) (models.Package, error) {
	return models.Package{
		PackageName:             module.Name,
		SPDXID:                  fmt.Sprintf("SPDXRef-Package-%s", module.Name),
		PackageVersion:          module.Version,
		PackageSupplier:         "NOASSERTION",
		PackageDownloadLocation: module.PackageURL,
		FilesAnalyzed:           false,
		PackageChecksum:         module.CheckSum.String(),
		PackageHomePage:         module.PackageURL,
		PackageLicenseConcluded: "NOASSERTION",
		PackageLicenseDeclared:  "NOASSERTION",
		PackageCopyrightText:    "NOASSERTION",
		PackageLicenseComments:  "NOASSERTION",
		PackageComment:          "NOASSERTION",
		RootPackage:             module.Root,
	}, nil
}
