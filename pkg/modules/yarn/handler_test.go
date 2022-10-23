// SPDX-License-Identifier: Apache-2.0

package yarn

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

func TestYarn(t *testing.T) {
	t.Run("test is valid", TestIsValid)
	t.Run("test has modules installed", TestHasModulesInstalled)
	t.Run("test get module", TestGetModule)
	t.Run("test list modules", TestListModules)
	t.Run("test list all modules", TestListAllModules)
}

func TestIsValid(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	valid := n.IsValid(path)
	invalid := n.IsValid(getPath())

	// Assert
	assert.Equal(t, true, valid)
	assert.Equal(t, false, invalid)
}

func TestHasModulesInstalled(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	installed := n.HasModulesInstalled(path)
	assert.NoError(t, installed)
	uninstalled := n.HasModulesInstalled(getPath())
	assert.Error(t, uninstalled)
}

func TestGetModule(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mod, err := n.GetRootModule(path)

	assert.NoError(t, err)
	assert.Equal(t, "create-react-app-lambda", mod.Name)
	assert.Equal(t, "", mod.Supplier.Name)
	assert.Equal(t, "0.5.0", mod.Version)
}

func TestListModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListUsedModules(path)

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

func TestListAllModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	var globalSettingFile string
	mods, err := n.ListModulesWithDeps(path, globalSettingFile)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {
		if mod.Name == "axios" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s", mod.Name))))
			assert.Equal(t, "0.19.2", mod.Version)
			assert.Equal(t, "https://registry.yarnpkg.com/axios/-/axios-0.19.2.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2014-present Matt Zabriskie", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "react" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s", mod.Name))))

			assert.Equal(t, "16.14.0", mod.Version)
			assert.Equal(t, "https://registry.yarnpkg.com/react/-/react-16.14.0.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) Facebook, Inc. and its affiliates.", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "react-dom" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(fmt.Sprintf("%s", mod.Name))))

			assert.Equal(t, "16.14.0", mod.Version)
			assert.Equal(t, "https://registry.yarnpkg.com/react-dom/-/react-dom-16.14.0.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
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
