package helper

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
	"os/exec"
	"spdx-sbom-generator/internal/licenses"
	"spdx-sbom-generator/internal/models"

	log "github.com/sirupsen/logrus"

	"github.com/go-enry/go-license-detector/v4/licensedb"
	"spdx-sbom-generator/internal/reader"
	"strings"
)

// FileExists ...
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// StringSliceIndex determines the index of a given string in a given string slice.
func StringSliceIndex(haystack []string, needle string) int {
	for i := range haystack {
		if haystack[i] == needle {
			return i
		}
	}
	return -1
}

func ExecCMD(modulePath string, writer io.Writer, cmdParameter ...string) error {
	cmd := exec.Command(cmdParameter[0], cmdParameter[1:]...)
	cmd.Dir = modulePath
	cmd.Stdout = writer
	return cmd.Run()
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
		log.Errorf("Could not read license file: %w", err)
		return ""
	}

	// extract license required segment
	return string(bytes)
}

// GetCopyright ...
func GetCopyright(content string) string {
	// split by paragraph
	paragraphs := strings.Split(content, "\n\n")
	for _, p := range paragraphs {
		lines := strings.Split(p, "\n")
		if len(lines) == 0 {
			continue
		}

		line := strings.TrimSpace(lines[0])
		tokens := strings.Fields(line)
		if len(tokens) == 0 {
			continue
		}
		if strings.Contains(strings.ToLower(tokens[0]), "copyright") {
			return line
		}
	}

	return ""
}

// GetCopyrightText ...
func GetCopyrightText(path string) string {
	r := reader.New(path)
	c := r.StringFromFile()
	ind := strings.Index(c, "Copyright (c)")
	if ind < 0 {
		return ""
	}
	copyWrite := strings.Split(c[ind:], "\n")
	return strings.TrimSuffix(copyWrite[0], "\r")
}

func ReadLockFile(path string) ([]Package, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	p := make([]Package, 0)
	i := -1
	scanner := bufio.NewScanner(file)

	isPk := false
	isDep := false
	for scanner.Scan() {
		text := scanner.Text()
		if strings.HasPrefix(scanner.Text(), "#") {
			continue
		}
		if strings.TrimSpace(text) == "" {
			isPk = false
			isDep = false
			continue
		}
		if isDep {
			p[i].Dependencies = append(p[i].Dependencies, text)
			continue
		}
		if isPk {
			if strings.HasPrefix(text, "  version ") {
				p[i].Version = strings.TrimSuffix(strings.TrimPrefix(strings.TrimPrefix(text, "  version "), "\""), "\"")
				n := p[i].Name[:strings.Index(p[i].Name, "@")]
				p[i].Name = fmt.Sprintf("%s-%s", n, p[i].Version)
				p[i].PkPath = p[i].PkPath[:strings.LastIndex(p[i].PkPath, "@")]
				continue
			}
			if strings.HasPrefix(text, "  resolved ") {
				p[i].Resolved = strings.TrimPrefix(text, "  resolved ")
				continue
			}
			if strings.HasPrefix(text, "  integrity ") {
				p[i].Integrity = strings.TrimPrefix(text, "  integrity ")
				continue
			}
			if strings.HasPrefix(text, "  dependencies:") {
				isDep = true
				continue
			}
		}

		if !strings.HasPrefix(scanner.Text(), "  ") {
			isPk = true
			i++
			var pak Package
			name := text
			name = strings.TrimSpace(name)
			if strings.Contains(name, ",") {
				s := strings.Split(name, ",")
				name = s[0]
			}
			name = strings.TrimPrefix(name, "\"")
			name = strings.TrimSuffix(name, ":")

			pak.PkPath = strings.TrimSuffix(name, "\"")
			name = strings.TrimPrefix(name, "@")

			pak.Name = name
			p = append(p, pak)
			continue
		}
		if strings.HasSuffix(scanner.Text(), ":") {

		}

	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return p, nil
}

type Package struct {
	Name         string
	PkPath       string
	Version      string
	Resolved     string
	Integrity    string
	Dependencies []string
}
