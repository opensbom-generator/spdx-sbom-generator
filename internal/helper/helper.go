package helper

import (
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"spdx-sbom-generator/internal/licenses"
	"spdx-sbom-generator/internal/models"

	"github.com/go-enry/go-license-detector/v4/licensedb"
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
					ExtractedText: "",
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
