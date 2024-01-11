// package mvnpom implements the plugin.Plugin interface
package mvnpom

import (
	"errors"
	"fmt"
	"path/filepath"
	"time"

	"github.com/spdx/spdx-sbom-generator/pkg/plugin"

	purl "github.com/package-url/packageurl-go"
	c "github.com/spdx/tools-golang/spdx/common"
	v2 "github.com/spdx/tools-golang/spdx/v2/common"
	"github.com/spdx/tools-golang/spdx/v2/v2_3"
	"github.com/vifraa/gopom"
	"golang.org/x/exp/slices"
)

// name is used to register this plugin
var name = "mvnpom"

// supportedSpdxVersions contains all supported SPDX versions for MvnPomPlugin
var supportedSpdxVersions = [1]string{"2.3"}

// supportedFormats contains all supported formats for MvnPomPlugin
var supportedFormats = [1]string{"json"}

var topSPDXPackageId v2.ElementID = "SPDXRef-0"

// MvnPomPlugin implements Plugin
type MvnPomPlugin struct {
	PluginPath  string // this Plugin requires a path to the pom.xml file
	SpdxVersion string // this Plugin requires an SPDX spec version
	SpdxFormat  string // this Plugin requires an SPDX format

}

// NewMvnPomPlugin returns a pointer to an MvnPomPlugin
// object with default values
// Ideally, this struct will also contain command line options
// for which a NewWithOptions function may be used
func NewMvnPomPlugin() *MvnPomPlugin {
	return &MvnPomPlugin{
		PluginPath:  ".",
		SpdxVersion: "2.3",
		SpdxFormat:  "json",
	}
}

// GetSpdxDocument returns an SPDX document of supported format
func (mpp MvnPomPlugin) GetSpdxDocument() (c.AnyDocument, error) {
	// return an error if the SPDX version is not supported
	s := supportedSpdxVersions[:]
	f := supportedFormats[:]
	if !slices.Contains(s, mpp.SpdxVersion) {
		return nil, errors.New("unsupported SPDX version")
	}
	if !slices.Contains(f, mpp.SpdxFormat) {
		return nil, errors.New("unsupported SPDX format")
	}
	// read the pom.xml file
	pomPath := filepath.Join(mpp.PluginPath, "pom.xml")
	parsedPom, err := gopom.Parse(pomPath)
	if err != nil {
		return nil, err
	}
	// create all structs
	// doc CreationInfo
	cinfo := v2_3.CreationInfo{
		Creators: getDocCreators(),
		Created:  getDocTimestamp(),
	}
	doc := v2_3.Document{
		SPDXVersion:       v2_3.Version,
		DataLicense:       v2_3.DataLicense,
		SPDXIdentifier:    "SPDXRef-DOCUMENT",
		DocumentName:      "example_mvn_pom_spdx",
		DocumentNamespace: fmt.Sprintf("http://spdx.org/documents/%s-%s", *parsedPom.ArtifactID, *parsedPom.Version),
		CreationInfo:      &cinfo,
		Packages:          getPomPackages(parsedPom),
	}
	return doc, nil
}

// init registers this plugin
func init() {
	mpp := NewMvnPomPlugin()
	if name != "" {
		plugin.Register(name, mpp)
	}
}

// unexported functions

func getDocCreators() []v2.Creator {
	var creators []v2.Creator
	tc := v2.Creator{
		Creator:     "pomtospdx",
		CreatorType: "Tool",
	}
	creators = append(creators, tc)
	return creators
}

func getDocTimestamp() string {
	t := time.Now()
	return fmt.Sprintf("%d-%02d-%02dT%02d:%02d:%02d",
		t.Year(), t.Month(), t.Day(), t.Hour(), t.Minute(), t.Second())
}

func getPomPackages(p *gopom.Project) []*v2_3.Package {
	var packages []*v2_3.Package
	// get the top package first
	tsupplier := v2.Supplier{
		Supplier:     *p.Organization.Name,
		SupplierType: "Organization",
	}
	tdl := purl.NewPackageURL("maven",
		*p.GroupID,
		*p.Name,
		*p.Version,
		nil,
		"")
	tpackage := v2_3.Package{
		IsUnpackaged:            false,
		PackageName:             *p.Name,
		PackageSPDXIdentifier:   topSPDXPackageId,
		PackageVersion:          *p.Version,
		PackageSupplier:         &tsupplier,
		PackageDownloadLocation: tdl.ToString(),
		FilesAnalyzed:           false,
		PackageLicenseDeclared:  "NOASSERTION",
		PrimaryPackagePurpose:   "APPLICATION",
	}
	packages = append(packages, &tpackage)
	// get declared dependencies
	for i, d := range *p.Dependencies {
		if d.Scope == nil {
			spdxid := fmt.Sprintf("SPDXRef-%d", i+1)
			pkg := v2_3.Package{
				PackageName:             *d.ArtifactID,
				PackageSPDXIdentifier:   v2.ElementID(spdxid),
				PackageVersion:          *d.Version,
				PackageSupplier:         getDepSupplier(d),
				PackageDownloadLocation: getDepPurl(d),
				FilesAnalyzed:           false,
			}
			packages = append(packages, &pkg)
		}

	}
	return packages
}

func getDepSupplier(d gopom.Dependency) *v2.Supplier {
	return &v2.Supplier{
		Supplier:     *d.GroupID,
		SupplierType: "Organization",
	}
}

func getDepPurl(d gopom.Dependency) string {
	ddl := purl.NewPackageURL("maven",
		*d.GroupID,
		*d.ArtifactID,
		*d.Version,
		nil,
		"")
	return ddl.ToString()
}
