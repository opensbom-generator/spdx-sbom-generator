// SPDX-License-Identifier: Apache-2.0

package format

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"

	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

const (
	noAssertion = "NOASSERTION"
	httpPrefix  = "http"
)

var replacer *strings.Replacer

// Format ...
type Format struct {
	Config Config
}

// Config ...
type Config struct {
	ToolVersion       string
	Filename          string
	OutputFormat      models.OutputFormat
	GetSource         func() []models.Module
	GlobalSettingFile string
}

func init() {
	replacers := []string{"/", ".", "_", "-"}
	replacer = strings.NewReplacer(replacers...)
}

// New ...
func New(cfg Config) (Format, error) {
	return Format{
		Config: cfg,
	}, nil
}

// SPDXRenderer is an interface that is to be implemented for every possible output format
type SPDXRenderer interface {
	RenderDocument(document models.Document) ([]byte, error)
}

// Render prepares and generates the final SPDX document in the specified format
func (f *Format) Render() error {
	modules := sortModules(f.Config.GetSource())
	document, err := buildBaseDocument(f.Config.ToolVersion, modules[0])
	if err != nil {
		return err
	}

	err = f.annotateDocumentWithPackages(modules, document)
	if err != nil {
		return err
	}

	file, err := os.Create(f.Config.Filename)
	if err != nil {
		return err
	}

	var spdxRenderer SPDXRenderer

	switch f.Config.OutputFormat {
	case models.OutputFormatSpdx:
		spdxRenderer = TagValueSPDXRenderer{}
	case models.OutputFormatJson:
		spdxRenderer = JsonSPDXRenderer{}
	}

	outputBytes, err := spdxRenderer.RenderDocument(*document)
	if err != nil {
		return err
	}

	// Write to file
	file.Write(outputBytes)
	file.Sync()

	return nil
}

func buildBaseDocument(toolVersion string, module models.Module) (*models.Document, error) {
	return &models.Document{
		SPDXVersion:       "SPDX-2.2",
		DataLicense:       "CC0-1.0",
		SPDXID:            "SPDXRef-DOCUMENT",
		DocumentName:      buildName(module.Name, module.Version),
		DocumentNamespace: buildNamespace(module.Name, module.Version),
		CreationInfo: models.CreationInfo{
			Creators: []string{fmt.Sprintf("Tool: spdx-sbom-generator-%s", toolVersion)},
			Created:  time.Now().UTC().Format(time.RFC3339),
		},
		Packages:                []models.Package{},
		Relationships:           []models.Relationship{},
		ExtractedLicensingInfos: []models.ExtractedLicensingInfo{},
	}, nil
}

// WIP
func (f *Format) annotateDocumentWithPackages(modules []models.Module, document *models.Document) error {
	for _, module := range modules {
		pkg, err := f.convertToPackage(module)
		if pkg.RootPackage {
			document.Relationships = append(document.Relationships, models.Relationship{
				SPDXElementID:      document.SPDXID,
				RelatedSPDXElement: pkg.SPDXID,
				RelationshipType:   "DESCRIBES",
			})
		}
		if err != nil {
			return fmt.Errorf("failed to convert module %w", err)
		}
		for _, subMod := range module.Modules {
			subPkg, err := f.convertToPackage(*subMod)
			if err != nil {
				return fmt.Errorf("failed to convert submodule %w", err)
			}
			document.Relationships = append(document.Relationships, models.Relationship{
				SPDXElementID:      pkg.SPDXID,
				RelatedSPDXElement: subPkg.SPDXID,
				RelationshipType:   "DEPENDS_ON",
			})
		}
		for licence := range module.OtherLicense {
			document.ExtractedLicensingInfos = append(document.ExtractedLicensingInfos, models.ExtractedLicensingInfo{
				LicenseID:      module.OtherLicense[licence].ID,
				ExtractedText:  module.OtherLicense[licence].ExtractedText,
				LicenseName:    module.OtherLicense[licence].Name,
				LicenseComment: module.OtherLicense[licence].Comments,
			})
		}
		document.Packages = append(document.Packages, pkg)
	}
	return nil
}

// WIP
func (f *Format) convertToPackage(module models.Module) (models.Package, error) {
	return models.Package{
		PackageName:             module.Name,
		SPDXID:                  setPkgSPDXID(module.Name, module.Version, module.Root),
		PackageVersion:          buildVersion(module),
		PackageSupplier:         setPkgValue(module.Supplier.Get()),
		PackageDownloadLocation: setPkgValue(module.PackageDownloadLocation),
		FilesAnalyzed:           false,
		PackageChecksums: []models.PackageChecksum{{
			Algorithm: module.CheckSum.Algorithm,
			Value:     module.CheckSum.String(),
		}},
		PackageHomePage:         buildHomepageURL(module.PackageURL),
		PackageLicenseConcluded: setPkgValue(module.LicenseConcluded),
		PackageLicenseDeclared:  setPkgValue(module.LicenseDeclared),
		PackageCopyrightText:    setPkgValue(module.Copyright),
		PackageLicenseComments:  setPkgValue(""),
		PackageComment:          setPkgValue(""),
		RootPackage:             module.Root,
	}, nil
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
