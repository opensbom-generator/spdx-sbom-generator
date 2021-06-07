// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"encoding/xml"
	"io"
	"io/ioutil"
)

// File ...
type File struct {
	Source string `xml:"src,attr"`
	Target string `xml:"target,attr"`
}

// Dependency ...
type Dependency struct {
	ID      string `xml:"id,attr"`
	Version string `xml:"version,attr"`
}

// NugetSpec ...
type NugetSpec struct {
	Name  xml.Name `xml:"package"`
	Xmlns string   `xml:"xmlns,attr,omitempty"`
	Meta  struct {
		ID               string `xml:"id"`
		Version          string `xml:"version"`
		Title            string `xml:"title,omitempty"`
		Authors          string `xml:"authors"`
		Owners           string `xml:"owners,omitempty"`
		LicenseURL       string `xml:"licenseUrl,omitempty"`
		License          string `xml:"license"`
		ProjectURL       string `xml:"projectUrl,omitempty"`
		IconURL          string `xml:"iconUrl,omitempty"`
		ReqLicenseAccept bool   `xml:"requireLicenseAcceptance"`
		Description      string `xml:"description"`
		ReleaseNotes     string `xml:"releaseNotes,omitempty"`
		Copyright        string `xml:"copyright,omitempty"`
		Summary          string `xml:"summary,omitempty"`
		Language         string `xml:"language,omitempty"`
		Tags             string `xml:"tags,omitempty"`
		Dependencies     struct {
			Dependency []Dependency `xml:"dependency"`
		} `xml:"dependencies,omitempty"`
		Repository struct {
			URL  string `xml:"url,attr"`
			Type string `xml:"type,attr"`
		} `xml:"repository,omitempty"`
	} `xml:"metadata"`
	Files struct {
		File []File `xml:"file"`
	} `xml:"files,omitempty"`
}

// PackageConfig ...
type PackageConfig struct {
	XMLName  xml.Name        `xml:"packages"`
	Packages []PackageDetail `xml:"package"`
}

// PackageDetail ...
type PackageDetail struct {
	XMLName xml.Name `xml:"package"`
	ID      string   `xml:"id,attr"`
	Version string   `xml:"version,attr"`
}

// ConvertedFromBytes ...
func ConvertFromBytes(specFile []byte) (*NugetSpec, error) {
	nugetSpec := NugetSpec{}
	err := xml.Unmarshal(specFile, &nugetSpec)
	if err != nil {
		return nil, err
	}
	return &nugetSpec, nil
}

// ConvertFromReader ...
func ConvertFromReader(reader io.ReadCloser) (*NugetSpec, error) {
	bytes, err := ioutil.ReadAll(reader)
	if err != nil {
		return nil, err
	}
	return ConvertFromBytes(bytes)
}
