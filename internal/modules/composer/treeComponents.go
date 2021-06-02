package composer

import (
	"bytes"
	"encoding/json"
	"errors"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type ComposerTreeList struct {
	Installed []ComposerTreeComponent
}
type ComposerTreeComponent struct {
	Name        string
	Version     string
	Description string
	Requires    []ComposerTreeComponent
}

func getTreeListFromComposerShowTree(path string) (ComposerTreeList, error) {
	cmdArgs := ShowModulesCmd.Parse()
	if cmdArgs[0] != "composer" {
		return ComposerTreeList{}, errors.New("no composer command")
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	buffer := new(bytes.Buffer)
	if err := command.Execute(buffer); err != nil {
		return ComposerTreeList{}, err
	}
	defer buffer.Reset()

	var graphModules ComposerTreeList
	err := json.NewDecoder(buffer).Decode(&graphModules)
	if err != nil {
		return ComposerTreeList{}, err
	}

	return graphModules, nil
}

func addTreeComponentsToModule(treeComponent ComposerTreeComponent, modules []models.Module) bool {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}
	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
	}

	rootLevelName := getName(treeComponent.Name)
	_, ok := moduleMap[rootLevelName]
	if !ok {
		return false
	}

	requires := treeComponent.Requires

	if requires == nil {
		return false
	}

	if len(requires) == 0 {
		return false
	}

	for _, subTreeComponent := range requires {
		childLevelName := getName(subTreeComponent.Name)
		childLevelModule, ok := moduleMap[childLevelName]
		if !ok {
			continue
		}

		addSubModuleToAModule(modules, moduleIndex[rootLevelName], childLevelModule)
		addTreeComponentsToModule(subTreeComponent, modules)
	}

	return true
}

func addSubModuleToAModule(modules []models.Module, moduleIndex int, subModule models.Module) {
	modules[moduleIndex].Modules[subModule.Name] = &models.Module{
		Name:             subModule.Name,
		Version:          subModule.Version,
		Path:             subModule.Path,
		LocalPath:        subModule.LocalPath,
		Supplier:         subModule.Supplier,
		PackageURL:       subModule.PackageURL,
		CheckSum:         subModule.CheckSum,
		PackageHomePage:  subModule.PackageHomePage,
		LicenseConcluded: subModule.LicenseConcluded,
		LicenseDeclared:  subModule.LicenseDeclared,
		CommentsLicense:  subModule.CommentsLicense,
		OtherLicense:     subModule.OtherLicense,
		Copyright:        subModule.Copyright,
		PackageComment:   subModule.PackageComment,
		Root:             subModule.Root,
	}
}
