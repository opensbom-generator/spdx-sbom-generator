// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"bufio"
	"fmt"
	"os/exec"
	"strings"

	"golang.org/x/mod/semver"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

func (description SwiftPackageDescription) Module() *models.Module {
	mod := &models.Module{}

	mod.Name = description.Name
	mod.Root = true
	mod.LocalPath = description.Path
	setLicense(mod, description.Path)
	setCheckSum(mod, description.Path)
	setVersion(mod, description.Path)

	return mod
}

func (dep SwiftPackageDependency) Module() *models.Module {
	mod := &models.Module{}
	mod.Name = dep.Name
	mod.PackageURL = strings.TrimSuffix(dep.Url, ".git")

	if strings.HasSuffix(dep.Url, ".git") {
		if strings.HasPrefix(dep.Url, "http") ||
			strings.HasPrefix(dep.Url, "ssh") ||
			strings.HasPrefix(dep.Url, "git@") {
			mod.PackageDownloadLocation = "git+" + dep.Url
		}
	}

	mod.Version = dep.Version
	mod.LocalPath = dep.Path
	setLicense(mod, dep.Path)
	setCheckSum(mod, dep.Path)

	return mod
}

func setLicense(mod *models.Module, path string) error {
	licensePkg, err := helper.GetLicenses(path)
	if err != nil {
		return err
	}

	mod.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
	mod.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
	if !helper.LicenseSPDXExists(licensePkg.ID) {
		licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
		mod.OtherLicense = append(mod.OtherLicense, licensePkg)
	}
	mod.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
	mod.CommentsLicense = licensePkg.Comments

	return nil
}

func setVersion(mod *models.Module, path string) error {
	cmd := exec.Command("git", "describe", "--tags", "--exact-match")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	scanner := bufio.NewScanner(strings.NewReader(string(output)))
	for scanner.Scan() {
		version := scanner.Text()

		// semver requires a "v" prefix
		if !strings.HasPrefix(version, "v") {
			version = "v" + version
		}

		if semver.IsValid(version) {
			mod.Version = version[1:] // remove the "v" prefix
			break
		}
	}

	return nil
}

func setCheckSum(mod *models.Module, path string) error {
	cmd := exec.Command("git", "rev-parse", "HEAD")
	cmd.Dir = path
	output, err := cmd.Output()
	if err != nil {
		return err
	}

	if len(output) > 0 {
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1, // FIXME: derive from git
			Value:     string(output),
		}
	}

	return nil
}
