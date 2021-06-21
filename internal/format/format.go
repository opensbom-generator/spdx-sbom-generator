// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	"github.com/gookit/color"
	"github.com/i582/cfmt/cmd/cfmt"
	"github.com/schollz/progressbar/v3"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

const (
	noAssertion = "NOASSERTION"
	httpPrefix  = "http"
)

var replacer *strings.Replacer

// Format ...
type Format struct {
	Config Config
	Client *helper.Client
}

// Config ...
type Config struct {
	ToolVersion string
	Filename    string
	GetSource   func() []models.Module
}

func init() {
	replacers := []string{"/", ".", "_", "-"}
	replacer = strings.NewReplacer(replacers...)
}

// New ...
func New(cfg Config) (Format, error) {
	return Format{
		Config: cfg,
		Client: helper.NewClient(),
	}, nil
}

// Build ...
// todo: refactor this Render into interface that different priting format can leverage
// move into go templates
func (f *Format) Render() error {
	modules := sortModules(f.Config.GetSource())
	document, err := buildDocument(f.Config.ToolVersion, modules[0])
	if err != nil {
		return err
	}

	packages, otherLicenses, err := f.buildPackages(modules)
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
	cfmt.Println(cfmt.Sprintf("{{Building output file: }}::cyan|bold`%s`", color.Yellow.Sprintf(f.Config.Filename)))
	bar := progressbar.Default(int64(len(packages)))
	for _, pkg := range packages {
		file.WriteString(fmt.Sprintf("##### Package representing the %s\n\n", pkg.PackageName))
		generatePackage(file, pkg)
		if pkg.RootPackage {
			file.WriteString(fmt.Sprintf("Relationship: %s DESCRIBES %s \n\n", document.SPDXID, pkg.SPDXID))
		}
		//Print DEPS ON
		if len(pkg.DependsOn) > 0 {
			for _, subPkg := range pkg.DependsOn {
				file.WriteString(fmt.Sprintf("Relationship: %s DEPENDS_ON %s \n", pkg.SPDXID, subPkg.SPDXID))
			}
			file.WriteString("\n")
		}
		bar.Add(1)
	}

	//Print Other Licenses
	if len(otherLicenses) > 0 {
		file.WriteString("##### Non-standard license\n\n")
		for lic := range otherLicenses {
			file.WriteString(fmt.Sprintf("LicenseID: %s\n", lic))
			file.WriteString(fmt.Sprintf("ExtractedText: %s\n", otherLicenses[lic].ExtractedText))
			file.WriteString(fmt.Sprintf("LicenseName: %s\n", otherLicenses[lic].Name))
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
	if pkg.PackageVersion != "" {
		file.WriteString(fmt.Sprintf("PackageVersion: %s\n", pkg.PackageVersion))
	}

	file.WriteString(fmt.Sprintf("PackageSupplier: %s\n", pkg.PackageSupplier))
	file.WriteString(fmt.Sprintf("PackageDownloadLocation: %s\n", pkg.PackageDownloadLocation))
	file.WriteString(fmt.Sprintf("FilesAnalyzed: %v\n", pkg.FilesAnalyzed))
	if !strings.Contains(pkg.PackageChecksum, noAssertion) {
		file.WriteString(fmt.Sprintf("PackageChecksum: %v\n", pkg.PackageChecksum))
	}
	file.WriteString(fmt.Sprintf("PackageHomePage: %v\n", pkg.PackageHomePage))
	file.WriteString(fmt.Sprintf("PackageLicenseConcluded: %v\n", pkg.PackageLicenseConcluded))
	file.WriteString(fmt.Sprintf("PackageLicenseDeclared: %v\n", pkg.PackageLicenseDeclared))
	file.WriteString(fmt.Sprintf("PackageCopyrightText: %v\n", pkg.PackageCopyrightText))
	file.WriteString(fmt.Sprintf("PackageLicenseComments: %v\n", pkg.PackageLicenseComments))
	file.WriteString(fmt.Sprintf("PackageComment: %v\n\n", pkg.PackageComment))
}

func buildDocument(toolVersion string, module models.Module) (*models.Document, error) {
	return &models.Document{
		SPDXVersion:       "SPDX-2.2",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      buildName(module.Name, module.Version),
		DocumentNamespace: buildNamespace(module.Name, module.Version),
		Creator:           fmt.Sprintf("Tool: spdx-sbom-generator-%s", toolVersion),
		Created:           time.Now().UTC().Format(time.RFC3339),
	}, nil
}

// WIP
func (f *Format) buildPackages(modules []models.Module) ([]models.Package, map[string]*models.License, error) {
	packages := make([]models.Package, len(modules))
	otherLicenses := map[string]*models.License{}
	for i, module := range modules {
		pkg, err := f.convertToPackage(module)
		if err != nil {
			return nil, nil, fmt.Errorf("failed to convert module %w", err)
		}

		subPackages := make([]models.Package, len(module.Modules))
		idx := 0
		for _, subMod := range module.Modules {
			subPkg, err := f.convertToPackage(*subMod)
			if err != nil {
				return nil, nil, err
			}
			subPackages[idx] = subPkg
			idx++
		}
		pkg.DependsOn = subPackages
		for l := range module.OtherLicense {
			otherLicenses[module.OtherLicense[l].ID] = module.OtherLicense[l]
		}
		packages[i] = pkg
	}

	return packages, otherLicenses, nil
}

// WIP
func (f *Format) convertToPackage(module models.Module) (models.Package, error) {
	return models.Package{
		PackageName:     module.Name,
		SPDXID:          setPkgSPDXID(module.Name, module.Version, module.Root),
		PackageVersion:  buildVersion(module),
		PackageSupplier: noAssertion,
		//PackageDownloadLocation: f.buildDownloadURL(module.PackageURL, module.Version),
		PackageDownloadLocation: noAssertion,
		FilesAnalyzed:           false,
		PackageChecksum:         module.CheckSum.String(),
		PackageHomePage:         buildHomepageURL(module.PackageURL),
		PackageLicenseConcluded: noAssertion, // setPkgValue(module.LicenseConcluded),
		PackageLicenseDeclared:  noAssertion, // setPkgValue(module.LicenseDeclared),
		PackageCopyrightText:    noAssertion, // setPkgValue(module.Copyright),
		PackageLicenseComments:  setPkgValue(""),
		PackageComment:          setPkgValue(""),
		RootPackage:             module.Root,
	}, nil
}

func (f *Format) buildDownloadURL(url, version string) string {
	if url == "" {
		return noAssertion
	}

	u := f.Client.ParseURL(url)
	if u == nil {
		return noAssertion
	}

	if !f.Client.CheckURL(u.String()) {
		return noAssertion
	}

	if u.Host == "github.com" {
		if version != "" {
			return fmt.Sprintf("%s/releases/tag/%s", u.String(), version)
		}
	}

	return u.String()
}

// todo: complete build package homepage rules
func buildHomepageURL(url string) string {
	if url == "" {
		return noAssertion
	}

	if strings.HasPrefix(url, httpPrefix) {
		return url
	}

	return fmt.Sprintf("https://%s", url)
}

func buildVersion(module models.Module) string {
	if module.Version != "" {
		return module.Version
	}

	if !module.Root {
		return module.Version
	}

	localGit, err := git.PlainOpen(module.LocalPath)
	if err != nil {
		return ""
	}

	head, err := localGit.Head()
	if err != nil {
		return ""
	}

	return head.Hash().String()[0:7]
}

func setPkgValue(s string) string {
	if s == "" {
		return noAssertion
	}

	return s
}

func setPkgSPDXID(s, v string, root bool) string {
	if root {
		return fmt.Sprintf("SPDXRef-Package-%s", replacer.Replace(s))
	}

	return fmt.Sprintf("SPDXRef-Package-%s-%s", replacer.Replace(s), v)
}

// todo: improve this logic
func sortModules(modules []models.Module) []models.Module {
	for i, m := range modules {
		if m.Root {
			modules = append(modules[:i], modules[i+1:]...)
			return append([]models.Module{m}, modules...)
		}
	}

	return modules
}

func buildNamespace(name, version string) string {
	uuid := uuid.New().String()
	if version == "" {
		return fmt.Sprintf("http://spdx.org/spdxpackages/%s-%s", name, uuid)
	}

	return fmt.Sprintf("http://spdx.org/spdxpackages/%s-%s-%s", name, version, uuid)
}

func buildName(name, version string) string {

	if version == "" {
		return name
	}

	return fmt.Sprintf("%s-%s", name, version)
}
