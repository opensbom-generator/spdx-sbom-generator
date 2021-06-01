// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"bytes"
	"encoding/json"
	"errors"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type ComposerProjectInfo struct {
	Name        string
	Description string
	Versions    []string
}

func (m *composer) getProjectInfo() (models.Module, error) {
	if err := m.buildCmd(projectInfoCmd, "."); err != nil {
		return models.Module{}, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return models.Module{}, err
	}
	defer buffer.Reset()

	var projectInfo ComposerProjectInfo

	err := json.NewDecoder(buffer).Decode(&projectInfo)
	if err != nil {
		return models.Module{}, err
	}
	if projectInfo.Name == "" {
		return models.Module{}, errors.New("root project info not found")
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
	module := models.Module{
		Name:       name,
		Version:    version,
		Root:       true,
		PackageURL: packageUrl,
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     checkSumValue,
		},
	}

	licensePkg, err := helper.GetLicenses(".")
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	}

	return module, nil
}
