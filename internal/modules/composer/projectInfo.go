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
	Versions    []string // "1.0.0+no-version-set"
	Licenses    []ComposerProjectInfoLincense
}

type ComposerProjectInfoLincense struct {
	Name string //  "name": "MIT License",
	Osi  string //"osi": "MIT",
	URL  string
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
		LicenseConcluded: project.Licenses[0].Osi,
		LicenseDeclared:  project.Licenses[0].Osi,
		CommentsLicense:  project.Licenses[0].Name,
		// Path:             subModule.Path,
		// LocalPath:        subModule.LocalPath,
		// Supplier:         subModule.Supplier,
		// PackageHomePage:  subModule.PackageHomePage,
		// OtherLicense:     subModule.OtherLicense,
		// Copyright:        subModule.Copyright,
		// PackageComment:   subModule.PackageComment,
	}

	return nodule, nil
}
