<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
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

<<<<<<< HEAD
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
=======
func (m *composer) getProjectInfo() (models.Module, error) {
	if err := m.buildCmd(projectInfoCmd, "."); err != nil {
		return models.Module{}, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
		return models.Module{}, err
	}
	defer buffer.Reset()

	var projectInfo ComposerProjectInfo

	err := json.NewDecoder(buffer).Decode(&projectInfo)
	if err != nil {
		return models.Module{}, err
	}
<<<<<<< HEAD
=======
	if projectInfo.Name == "" {
		return models.Module{}, errors.New("root project info not found")
	}
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb

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
<<<<<<< HEAD
	nodule := models.Module{
=======
	module := models.Module{
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
		Name:       name,
		Version:    version,
		Root:       true,
		PackageURL: packageUrl,
		CheckSum: &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     checkSumValue,
		},
<<<<<<< HEAD
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
=======
	}

	licensePkg, err := helper.GetLicenses(".")
	if err == nil {
		module.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		module.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		module.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		module.CommentsLicense = licensePkg.Comments
	}

	return module, nil
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
}
