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

func getProjectInfo() (models.Module, error) {
	cmdArgs := ShowModulesCmd.Parse()
	if cmdArgs[0] != "composer" {
		return models.Module{}, errors.New("no composer command")
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: ".",
	})

	buffer := new(bytes.Buffer)
	if err := command.Execute(buffer); err != nil {
		return models.Module{}, err
	}
	defer buffer.Reset()

	var projectInfo ComposerProjectInfo

	err := json.NewDecoder(buffer).Decode(&projectInfo)
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
