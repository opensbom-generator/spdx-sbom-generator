package parsers

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	gomod "github.com/opensbom-generator/parsers/go"
	"github.com/opensbom-generator/parsers/meta"
	"github.com/opensbom-generator/parsers/pip"
	"github.com/opensbom-generator/parsers/plugin"
	log "github.com/sirupsen/logrus"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
	"github.com/spdx/tools-golang/json"
	"github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/spdx/tools-golang/tagvalue"
)

var (
	errNoPluginSupported = errors.New("no plugins supported for current path")
	DefaultPlugins       = []plugin.Plugin{pip.New(), gomod.New()}
	replacer             *strings.Replacer
)

const (
	noAssertion = "NOASSERTION"
	httpPrefix  = "http"
)

type PluginManager interface {
	Init() error
	Generate() error
}

type pluginManager struct {
	registeredPlugins []plugin.Plugin
	validPlugin       plugin.Plugin
	cfg               Config
}

type Config struct {
	Version           string
	License           bool
	Depth             string
	OutputDir         string
	Schema            string
	Format            models.OutputFormat
	GlobalSettingFile string
	Path              string
	PluginsToRegister []plugin.Plugin
}

func NewPluginManager(cfg Config) PluginManager {
	return &pluginManager{
		registeredPlugins: cfg.PluginsToRegister,
		cfg:               cfg,
	}
}

func (pm *pluginManager) Init() error {
	replacers := []string{"/", ".", "_", "-"}
	replacer = strings.NewReplacer(replacers...)

	for _, p := range pm.registeredPlugins {
		path := pm.cfg.Path
		if p.IsValid(path) {
			if err := p.SetRootModule(path); err != nil {
				return err
			}

			if p != nil {
				pm.validPlugin = p
				return nil
			}
		}
	}

	return errNoPluginSupported
}

func (pm *pluginManager) Generate() error {
	validPlugin := pm.validPlugin
	metadata := validPlugin.GetMetadata()
	filename := fmt.Sprintf("bom-%s.%s", metadata.Slug, pm.cfg.Format.String())
	outputFile := filepath.Join(pm.cfg.OutputDir, filename)
	globalSettingFile := pm.cfg.GlobalSettingFile

	log.Infof("Running generator for `%s` with output `%s`", metadata.Slug, outputFile)

	modulePath := pm.cfg.Path
	version, err := validPlugin.GetVersion()
	if err != nil {
		return err
	}

	log.Infof("Current Language Version %s", version)
	log.Infof("Global Setting File %s", globalSettingFile)
	if moduleErr := validPlugin.HasModulesInstalled(modulePath); moduleErr != nil {
		return moduleErr
	}

	modules, err := validPlugin.ListModulesWithDeps(modulePath, globalSettingFile)
	if err != nil {
		log.Error(err)
		return err
	}

	modules = sortModules(modules)
	mod := modules[0]
	document := &v2_3.Document{
		SPDXVersion:       "SPDX-2.3",
		DataLicense:       "CC0-1.0",
		DocumentName:      buildName(mod.Name, mod.Version),
		DocumentNamespace: buildNamespace(mod.Name, mod.Version),
		CreationInfo: &v2_3.CreationInfo{
			Creators: []common.Creator{{
				Creator:     fmt.Sprintf("spdx-sbom-generator-%s", pm.cfg.Version),
				CreatorType: "Tool",
			}},
			Created: time.Now().UTC().Format(time.RFC3339),
		},
		Packages:                   nil,
		Relationships:              nil,
		SPDXIdentifier:             "DOCUMENT",
		ExternalDocumentReferences: nil,
		DocumentComment:            "",
		Files:                      nil,
		OtherLicenses:              nil,
		Annotations:                nil,
		Snippets:                   nil,
		Reviews:                    nil,
	}

	err = annotateDocumentWithPackages(modules, document)
	if err != nil {
		return err
	}

	file, err := os.Create(outputFile)
	if err != nil {
		return err
	}

	switch pm.cfg.Format {
	case models.OutputFormatSpdx:
		err = tagvalue.Write(document, file)
		if err != nil {
			return err
		}
	case models.OutputFormatJson:
		err = json.Write(document, file, json.EscapeHTML(true), json.Indent("\t"))
		if err != nil {
			return err
		}
	}

	return nil
}

func sortModules(modules []meta.Package) []meta.Package {
	var rootModule meta.Package

	for i, m := range modules {
		if m.Root {
			rootModule = m
			modules = append(modules[:i], modules[i+1:]...)
			break
		}
	}

	return append([]meta.Package{rootModule}, modules...)
}

func annotateDocumentWithPackages(modules []meta.Package, document *v2_3.Document) error {
	for _, module := range modules {
		pkg := convertToPackage(module)
		// TODO: is IsUnpackaged same as checking for root package
		if pkg.IsUnpackaged {
			document.Relationships = append(document.Relationships, &v2_3.Relationship{
				RefA: common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  document.SPDXIdentifier,
					SpecialID:     "",
				},
				RefB: common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  pkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				// Relationship is documented here
				// https://spdx.github.io/spdx-spec/v2.3/relationships-between-SPDX-elements/
				Relationship:        "DESCRIBES",
				RelationshipComment: "",
			})
		}

		for _, subMod := range module.Packages {
			subPkg := convertToPackage(*subMod)

			document.Relationships = append(document.Relationships, &v2_3.Relationship{
				RefA: common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  pkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				RefB: common.DocElementID{
					DocumentRefID: "",
					ElementRefID:  subPkg.PackageSPDXIdentifier,
					SpecialID:     "",
				},
				Relationship:        "DEPENDS_ON",
				RelationshipComment: "",
			})
		}
		for licence := range module.OtherLicense {
			document.OtherLicenses = append(document.OtherLicenses, &v2_3.OtherLicense{
				LicenseIdentifier: module.OtherLicense[licence].ID,
				ExtractedText:     module.OtherLicense[licence].ExtractedText,
				LicenseName:       module.OtherLicense[licence].Name,
				LicenseComment:    module.OtherLicense[licence].Comments,
			})
		}
		document.Packages = append(document.Packages, pkg)
	}
	return nil
}

func convertToPackage(module meta.Package) *v2_3.Package {
	return &v2_3.Package{
		PackageName:             module.Name,
		PackageSPDXIdentifier:   setPkgSPDXIdentifier(module.Name, module.Version, module.Root),
		PackageVersion:          buildVersion(module),
		PackageSupplier:         setPkgValue(module.Supplier.Get()),
		PackageDownloadLocation: module.PackageDownloadLocation,
		FilesAnalyzed:           false,
		PackageChecksums: []common.Checksum{{
			Algorithm: common.ChecksumAlgorithm(module.Checksum.Algorithm),
			Value:     module.Checksum.Value,
		}},
		PackageHomePage:         buildHomepageURL(module.PackageURL),
		PackageLicenseConcluded: noAssertion,
		PackageLicenseDeclared:  noAssertion,
		PackageCopyrightText:    noAssertion,
		PackageLicenseComments:  module.CommentsLicense,
		PackageComment:          module.PackageComment,
		IsUnpackaged:            module.Root,
	}
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

func buildVersion(module meta.Package) string {
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

func setPkgValue(s string) *common.Supplier {
	if s == "" {
		return nil
	}

	return &common.Supplier{
		Supplier:     s,
		SupplierType: "",
	}
}

func setPkgSPDXIdentifier(s, v string, root bool) common.ElementID {
	if root {
		return common.ElementID(replacer.Replace(s))
	}

	return common.ElementID(fmt.Sprintf("%s-%s", replacer.Replace(s), v))
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
