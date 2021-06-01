package yarn

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os/exec"
	"spdx-sbom-generator/internal/models"
	"strings"
	"testing"
)

func TestYarn(t *testing.T) {
	t.Run("test is valid", TestYarn_IsValid)
	t.Run("test has modules installed", TestYarn_HasModulesInstalled)
	t.Run("test get module", TestYarn_GetModule)
	t.Run("test list modules", TestYarn_ListModules)
	t.Run("test list all modules", TestYarn_ListAllModules)
}

func TestYarn_IsValid(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	valid := n.IsValid(path)
	invalid := n.IsValid(getPath())

	// Assert
	assert.Equal(t, true, valid)
	assert.Equal(t, false, invalid)
}

func TestYarn_HasModulesInstalled(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	installed := n.HasModulesInstalled(path)
	assert.NoError(t, installed)
	uninstalled := n.HasModulesInstalled(getPath())
	assert.Error(t, uninstalled)
}

func TestYarn_GetModule(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.GetModule(path)

	assert.NoError(t, err)
	assert.Equal(t, "create-react-app-lambda", mods[0].Name)
	assert.Equal(t, "", mods[0].Supplier.Name)
	assert.Equal(t, "0.5.0", mods[0].Version)

}

func TestYarn_ListModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListModules(path)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {

		if mod.Name == "axios" {
			assert.Equal(t, "axios", mod.Name)
			assert.Equal(t, "0.19.0", mod.Version)
			count++
			continue
		}

		if mod.Name == "react" {
			assert.Equal(t, "react", mod.Name)
			assert.Equal(t, "16.8.6", mod.Version)
			count++
			continue
		}
		if mod.Name == "react-dom" {
			assert.Equal(t, "react-dom", mod.Name)
			assert.Equal(t, "16.8.6", mod.Version)
			count++
			continue
		}
	}

	assert.Equal(t, 3, count)
}

func TestYarn_ListAllModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListAllModules(path)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {
		if mod.Name == "axios-0.19.2" {
			assert.Equal(t, "0.19.2", mod.Version)
			assert.Equal(t, "https://registry.yarnpkg.com/axios/-/axios-0.19.2.tgz#3ea36c5d8818d0d5f8a8a97a6d36b86cdc00cb27", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha512"), mod.CheckSum.Algorithm)
			assert.Equal(t, "fjgm5MvRHLhx+osE2xoekY70AhARk3a6hkN+3Io1jc00jtquGvxYlKlsFUhmUET0V5te6CcZI7lcv2Ym61mjHA==", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2014-present Matt Zabriskie", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "react-16.14.0" {
			assert.Equal(t, "16.14.0", mod.Version)
			assert.Equal(t, "https://registry.yarnpkg.com/react/-/react-16.14.0.tgz#94d776ddd0aaa37da3eda8fc5b6b18a4c9a3114d", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha512"), mod.CheckSum.Algorithm)
			assert.Equal(t, "0X2CImDkJGApiAlcf0ODKIneSwBPhqJawOa5wCtKbu7ZECrmS26NvtSILynQ66cgkT/RJ4LidJOc3bUESwmU8g==", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) Facebook, Inc. and its affiliates.", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "react-dom-16.14.0" {
			assert.Equal(t, "16.14.0", mod.Version)
			assert.Equal(t, "https://registry.yarnpkg.com/react-dom/-/react-dom-16.14.0.tgz#7ad838ec29a777fb3c75c3a190f661cf92ab8b89", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha512"), mod.CheckSum.Algorithm)
			assert.Equal(t, "1gCeQXDLoIqMgqD3IO2Ah9bnf0w9kzhwN5q4FGnHZ67hBm9yePzB5JJAIQCc8x3pFnNlwFq4RidZggNAAkzWWw==", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) Facebook, Inc. and its affiliates.", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
	}

	assert.Equal(t, 3, count)
}

func getPath() string {
	cmd := exec.Command("pwd")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(string(output), "\n")

	return path
}
