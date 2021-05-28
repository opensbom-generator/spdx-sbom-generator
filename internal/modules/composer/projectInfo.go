package composer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type ComposerProjectInfo struct {
	Name        string
	Description string
	Versions    []string
}

func getProjectInfo() (models.Module, error) {

	buf := new(bytes.Buffer)
	if err := helper.ExecCMD(".", buf, "composer", "show", "-s", "-f", "json"); err != nil {
		return models.Module{}, fmt.Errorf("Get Project Info failed: %w", err)
	}
	defer buf.Reset()

	var projectInfo ComposerProjectInfo

	err := json.NewDecoder(buf).Decode(&projectInfo)
	if err != nil {
		return models.Module{}, err
	}

	module, err := convertProjectInfoToModule(projectInfo)
	if err != nil {
		return models.Module{}, err
	}

	return module, nil
}

func convertProjectInfoToModule(project ComposerProjectInfo) (models.Module, error) {
	version := normalizePackageVersion(project.Versions[0])
	packageUrl := genComposerUrl(project.Name, version)
	checkSumValue := readCheckSum(packageUrl)
	name := getName(project.Name)
	nodule := models.Module{
		Name:       name,
		Version:    version,
		Root:       true,
		PackageURL: packageUrl,
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     checkSumValue,
		},
		LicenseConcluded: getProjectLicense(),
		LicenseDeclared:  getProjectLicense(),
	}

	return nodule, nil
}

func getProjectLicense() string {
	path := "."
	lic, err := helper.GetLicenses(path)
	if err != nil {
		return ""
	}

	return lic.Name
}
