// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"bufio"
	"encoding/json"
	"os"
	"path"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"strings"
)

const ProjectUrl = "pypi.org/project"
const PackageUrl = "pypi.org/pypi"
const SitePackage = "site-packages"
const PackageDistInfoPath = ".dist-info"
const PackageLicenseFile = "LICENSE"
const PackageMetadataFie = "METADATA"
const PackageWheelFie = "WHEEL"

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
	Name      string `json:"name,omitempty"`
	Version   string `json:"version,omitempty"`
	Location  string `json:"location,omitempty"`
	Installer string `json:"installer,omitempty"`
	Root      bool
}

type Metadata struct {
	Root           bool
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
	var distInfoPath string
	var exists bool
	var isSitePackage bool

	if strings.Contains(location, SitePackage) {
		isSitePackage = true
	}

	if isSitePackage {
		distInfoPath, exists = checkIfDistInfoPathExists(location, name, version)
		if exists {
			return distInfoPath
		}
		distInfoPath, exists = checkIfDistInfoPathExists(location, strings.ReplaceAll(name, "-", "_"), version)
	} else {
		distInfoPath = location
	}
	return distInfoPath
}

func checkIfDistInfoPathExists(location string, name string, version string) (string, bool) {
	var distInfoPath string

	package_name := name + "-" + version
	package_metadata := package_name + PackageDistInfoPath
	paths := []string{location, package_metadata}

	distInfoPath = path.Join(paths...)

	return distInfoPath, helper.Exists(distInfoPath)
}

func BuildLicenseUrl(distInfoLocation string) string {
	paths := []string{distInfoLocation, PackageLicenseFile}
	return path.Join(paths...)
}

func BuildMetadataPath(distInfoLocation string) string {
	paths := []string{distInfoLocation, PackageMetadataFie}
	return path.Join(paths...)
}

func BuildWheelPath(distInfoLocation string) string {
	paths := []string{distInfoLocation, PackageWheelFie}
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

func GetPackageChecksum(packagename string, packageJsonURL string, packageWheelPath string) *models.CheckSum {
	checkfortag := true

	wheeltag, err := GetWheelDistributionLastTag(packageWheelPath)
	if err != nil {
		checkfortag = false
	}
	if checkfortag && len(wheeltag) == 0 {
		checkfortag = false
	}

	checksum := getPypiPackageChecksum(packagename, packageJsonURL, checkfortag, wheeltag)
	return &checksum
}

func GetWheelDistributionLastTag(packageWheelPath string) (string, error) {
	if !helper.Exists(packageWheelPath) {
		return "", errorWheelFileNotFound
	}

	file, err := os.Open(packageWheelPath)
	if err != nil {
		return "", errorUnableToOpenWheelFile
	}
	defer file.Close()

	lasttag := ""
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		res := strings.Split(scanner.Text(), ":")
		if strings.Compare(strings.ToLower(res[0]), "tag") == 0 {
			lasttag = strings.TrimSpace(res[1])
		}
	}

	return lasttag, nil
}
