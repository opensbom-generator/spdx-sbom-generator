// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"encoding/json"
	"errors"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/go-enry/go-license-detector/v4/licensedb"
	log "github.com/sirupsen/logrus"

	"github.com/spdx/spdx-sbom-generator/pkg/licenses"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

const copyrightLookup = "copyright"

// copyright matching level of prefernece
const (
	matchLevel1 = iota
	matchLevel2
	matchLevel3
)

var re *regexp.Regexp

func init() {
	re = regexp.MustCompile(`^\d{4}$|^\d{4}-\d{4}$|^\(c\)$`)
}

type FileInfo struct {
	Path string `json:"path,omitempty"`
}

type copyrightMap map[int]string

func (c copyrightMap) get() string {
	if c[matchLevel1] != "" {
		return c[matchLevel1]
	}

	if c[matchLevel2] != "" {
		return c[matchLevel2]
	}

	if c[matchLevel3] != "" {
		return c[matchLevel3]
	}

	return ""
}

// Exists ...
func Exists(filepath string) bool {
	if _, err := os.Stat(filepath); os.IsNotExist(err) {
		return false
	}

	return true
}

// GetLicenses ...
func GetLicenses(modulePath string) (*models.License, error) {
	if modulePath != "" {
		licenses := licensedb.Analyse(modulePath)
		for i := range licenses {
			for j := range licenses[i].Matches {
				//returns the first element, the best match
				return &models.License{ID: licenses[i].Matches[j].License,
					Name:          licenses[i].Matches[j].License,
					ExtractedText: extractLicenseContent(modulePath, licenses[i].Matches[j].File),
					Comments:      "",
					File:          licenses[i].Matches[j].File}, nil
			}
		}
	}
	return nil, errors.New(fmt.Sprintf("could not detect license for %s\n", modulePath))
}

// LicenseExist ...
func LicenseSPDXExists(license string) bool {
	if _, ok := licenses.DB[license]; !ok {
		return false
	}
	return true
}

// BuildModuleName ...
func BuildModuleName(path, replacePath, DirReplace string) string {
	if replacePath != "" {
		if !Exists(DirReplace) {
			return replacePath
		}
	}
	return path
}

// BuildLicenseDeclared ...
// todo build rules to generate LicenseDeclated
func BuildLicenseDeclared(license string) string {
	if LicenseSPDXExists(license) {
		return license
	}
	return fmt.Sprintf("LicenseRef-%s", license)
}

// BuildLicenseConcluded ...
// todo build rules to generate LicenseConcluded
func BuildLicenseConcluded(license string) string {
	if LicenseSPDXExists(license) {
		return license
	}
	return fmt.Sprintf("LicenseRef-%s", license)
}

// todo: figure out how to extract only required text
func extractLicenseContent(path, filename string) string {
	bytes, err := ioutil.ReadFile(fmt.Sprintf("%s/%s", path, filename))
	if err != nil {
		log.Errorf("Could not read license file: %v", err)
		return ""
	}

	// extract license required segment
	return string(bytes)
}

// GetCopyright parses the license file found at plugin module or vendor folder
// Extract the text found starting with the keyword 'Copyright (c)' and until the newline
func GetCopyright(content string) string {
	cr := make(copyrightMap, 0)
	// split by paragraph
	paragraphs := strings.Split(content, "\n\n")
	for _, p := range paragraphs {
		if !strings.Contains(strings.ToLower(p), copyrightLookup) {
			continue
		}

		lines := strings.Split(p, "\n")
		if len(lines) == 0 {
			continue
		}

		line := strings.TrimSpace(lines[0])
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}

		if strings.EqualFold(copyrightLookup, tokens[0]) {
			cr[matchLevel2] = line
			if re.MatchString(tokens[1]) {
				cr[matchLevel1] = line
			}
		}

		for _, l := range lines {
			if strings.HasPrefix(strings.TrimSpace(strings.ToLower(l)), copyrightLookup) {
				cr[matchLevel3] = strings.TrimSpace(l)
				break
			}
		}
	}

	return cr.get()
}

// BuildManifestContent builds a content with directory tree
func BuildManifestContent(path string) []byte {
	manifest := []FileInfo{}
	err := filepath.Walk(path, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		manifest = append(manifest, FileInfo{
			Path: path,
		})
		return nil
	})

	if err == nil && len(manifest) > 0 {
		manifestBytes, err := json.Marshal(manifest)
		if err == nil {
			return manifestBytes
		}
	}
	return nil
}

func RemoveURLProtocol(url string) string {
	trimmedURL := strings.TrimSpace(url)
	trimmedURL = strings.TrimPrefix(trimmedURL, "https://")
	trimmedURL = strings.TrimPrefix(trimmedURL, "http://")
	return trimmedURL
}
