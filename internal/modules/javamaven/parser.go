package javamaven

import (
	"encoding/xml"
	"io"
)

// For POM.xml file parsing
type MavenPomProject struct {
	Parent                 Parent                 `xml:"parent"`
	Name                   string                 `xml:"name"`
	Url                    string                 `xml:"url"`
	XMLName                xml.Name               `xml:"project"`
	ModelVersion           string                 `xml:"modelVersion"`
	GroupId                string                 `xml:"groupId"`
	ArtifactId             string                 `xml:"artifactId"`
	Version                string                 `xml:"version"`
	Packaging              string                 `xml:"packaging"`
	Repositories           []Repository           `xml:"repositories>repository"`
	Properties             Properties             `xml:"properties"`
	Build                  Build                  `xml:"build"`
	Dependencies           []Dependency           `xml:"dependencies>dependency"`
	DependencyManagement   DependencyManagement   `xml:"dependencyManagement"`
	DistributionManagement DistributionManagement `xml:"distributionManagement"`
	Developers             Developer              `xml:"developers>developer"`
	Licenses               []License              `xml:"licenses>license"`
	Modules                []string               `xml:"modules>module"`
	PluginRepositories     []PluginRepository     `xml:"pluginRepositories>pluginRepository"`
	Profiles               []Profile              `xml:"profiles"`
}

// parent of the project
type Parent struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Build
type Build struct {
	Plugins          []Plugin `xml:"plugins>plugin"`
	PluginManagement []Plugin `xml:"pluginManagement>plugins>plugin"`
}

// dependency of the project
type Dependency struct {
	XMLName    xml.Name    `xml:"dependency"`
	GroupId    string      `xml:"groupId"`
	ArtifactId string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Classifier string      `xml:"classifier"`
	Type       string      `xml:"type"`
	Scope      string      `xml:"scope"`
	Exclusions []Exclusion `xml:"exclusions>exclusion"`
}

// DependencyManagement contains dependency elements whose version is stored in properties tag
type DependencyManagement struct {
	Dependencies []Dependency `xml:"dependencies>dependency"`
}

// DistributionManagement of the project
type DistributionManagement struct {
	DownloadUrl string `xml:"downloadUrl"`
	Status      string `xml:"status"`
}

// Developer of the project
type Developer struct {
	Name         string `xml:"name"`
	Email        string `xml:"email"`
	Organization string `xml:"organization"`
}

// License element of the project
type License struct {
	Name string `xml:"name"`
}

// An exclusion
type Exclusion struct {
	XMLName    xml.Name `xml:"exclusion"`
	GroupId    string   `xml:"groupId"`
	ArtifactId string   `xml:"artifactId"`
}

// A repository
type Repository struct {
	Id   string `xml:"id"`
	Name string `xml:"name"`
	Url  string `xml:"url"`
}

// Properties map
type Properties map[string]string

// A pluginRepository information
type PluginRepository struct {
	Id   string `xml:"id"`
	Name string `xml:"name"`
	Url  string `xml:"url"`
}

// A profile information
type Profile struct {
	Id    string `xml:"id"`
	Build Build  `xml:"build"`
}

// Plugin information
type Plugin struct {
	XMLName    xml.Name `xml:"plugin"`
	GroupId    string   `xml:"groupId"`
	ArtifactId string   `xml:"artifactId"`
	Version    string   `xml:"version"`
}

func (properties *Properties) UnmarshalXML(decoder *xml.Decoder, startElement xml.StartElement) error {
	*properties = map[string]string{}
	for {
		key := ""
		value := ""
		token, err := decoder.Token()
		// check end of file
		if err == io.EOF {
			break
		}
		switch tokenType := token.(type) {
		case xml.StartElement:
			key = tokenType.Name.Local
			err := decoder.DecodeElement(&value, &startElement)
			if err != nil {
				return err
			}
			(*properties)[key] = value
		}
	}
	return nil
}
