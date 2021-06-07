// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"encoding/json"
	"path"
	"strings"
)

const ProjectUrl = "pypi.org/project"
const PackageUrl = "pypi.org/pypi"
const PackageDistInfoPath = ".dist-info"
const PackageLicenseFile = ".dist-info/LICENSE"
const PackageMetadataFie = ".dist-info/METADATA"
const PackageWheelFie = ".dist-info/WHEEL"

// NOASSERTION constant
const NoAssertion = "NOASSERTION"

const (
	KeyName        string = "name"
	KeyVersion     string = "version"
	KeySummary     string = "summary"
	KeyHomePage    string = "home-page"
	KeyAuthor      string = "author"
	KeyAuthorEmail string = "author-email"
	KeyLicense     string = "license"
	KeyLocation    string = "location"
	KeyRequires    string = "requires"
)

var AuthorAnOrganizationKeywords = []string{"Authority", "Team", "Developers", "Services", "Foundation", "Software"}

type Packages struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}
type Metadata struct {
	Name           string
	Version        string
	Description    string
	ProjectURL     string
	PackageURL     string
	PackageJsonURL string
	HomePage       string
	Author         string
	AuthorEmail    string
	License        string
	DistInfoPath   string
	LicensePath    string
	MetadataPath   string
	WheelPath      string
	Location       string
	LocalPath      string
	Modules        []string
}

func LoadModules(data string) []Packages {
	var _modules []Packages
	json.Unmarshal([]byte(data), &_modules)
	return _modules
}

func BuildProjectUrl(name string, version string) string {
	paths := []string{ProjectUrl, name, version}
	return path.Join(paths...)
}

func BuildPackageUrl(name string, version string) string {
	paths := []string{PackageUrl, name, version}
	return path.Join(paths...)
}

func BuildPackageJsonUrl(name string, version string) string {
	paths := []string{PackageUrl, name, version, "json"}
	return path.Join(paths...)
}

func BuildLocalPath(location string, name string) string {
	paths := []string{location, name}
	return path.Join(paths...)
}

func BuildDistInfoPath(location string, name string, version string) string {
	package_name := name + "-" + version
	package_metadata := package_name + PackageDistInfoPath
	paths := []string{location, package_metadata}
	return path.Join(paths...)
}

func BuildLicenseUrl(location string, name string, version string) string {
	package_name := name + "-" + version
	package_license := package_name + PackageLicenseFile
	paths := []string{location, package_license}
	return path.Join(paths...)
}

func BuildMetadataPath(location string, name string, version string) string {
	package_name := name + "-" + version
	package_metadata := package_name + PackageMetadataFie
	paths := []string{location, package_metadata}
	return path.Join(paths...)
}

func BuildWheelPath(location string, name string, version string) string {
	package_name := name + "-" + version
	package_wheel := package_name + PackageWheelFie
	paths := []string{location, package_wheel}
	return path.Join(paths...)
}

func SetMetadataToNoAssertion(metadata *Metadata, packagename string) {
	metadata.Name = packagename
	metadata.Version = NoAssertion
	metadata.Description = NoAssertion
	metadata.HomePage = NoAssertion
	metadata.Author = NoAssertion
	metadata.AuthorEmail = NoAssertion
	metadata.License = NoAssertion
	metadata.LocalPath = NoAssertion
	metadata.Modules = []string{}
}

func IsAuthorAnOrganization(author string, authoremail string) bool {
	// If both Author and Author-Email are defined as "None", we assume it as Organization
	if (strings.Compare(strings.ToLower(author), "none") == 0) &&
		(strings.Compare(strings.ToLower(authoremail), "none") == 0) {
		return true
	}

	result := false
	// If Author fields has any one of the keywords, we assume it as Organization
	for _, v := range AuthorAnOrganizationKeywords {
		if strings.Contains(strings.ToLower(author), strings.ToLower(v)) {
			result = true
			break
		}
	}
	return result
}
