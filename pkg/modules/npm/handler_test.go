// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"crypto/sha256"
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

func TestNPM(t *testing.T) {
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
	assert.Equal(t, "e-commerce", mod.Name)
	assert.Equal(t, "ahmed saber", mod.Supplier.Name)
	assert.Equal(t, "1.0.0", mod.Version)

}

func TestListModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListUsedModules(path)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {

		if mod.Name == "bcryptjs" {
			assert.Equal(t, "bcryptjs", mod.Name)
			assert.Equal(t, "2.4.3", mod.Version)
			count++
			continue
		}

		if mod.Name == "body-parser" {
			assert.Equal(t, "body-parser", mod.Name)
			assert.Equal(t, "1.18.3", mod.Version)
			count++
			continue
		}
		if mod.Name == "shortid" {
			assert.Equal(t, "shortid", mod.Name)
			assert.Equal(t, "2.2.13", mod.Version)
			count++
			continue
		}

		if mod.Name == "validator" {
			assert.Equal(t, "validator", mod.Name)
			assert.Equal(t, "10.7.1", mod.Version)
			count++
			continue
		}
	}

	assert.Equal(t, 4, count)
}

func TestListAllModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	var globalSettingFile string
	mods, err := n.ListModulesWithDeps(path, globalSettingFile)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {
		if mod.Name == "validator" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))

			assert.Equal(t, "10.11.0", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/validator/-/validator-10.11.0.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2018 Chris O'Hara <cohara87@gmail.com>", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "shortid" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))

			assert.Equal(t, "2.2.16", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/shortid/-/shortid-2.2.16.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) Dylan Greene", mod.Copyright)
			assert.Equal(t, "MITNFA", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "body-parser" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))

			assert.Equal(t, "1.19.0", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/body-parser/-/body-parser-1.19.0.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2014 Jonathan Ong <me@jongleberry.com>", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "bcryptjs" {
			h := fmt.Sprintf("%x", sha256.Sum256([]byte(mod.Name)))
			assert.Equal(t, "2.4.3", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/bcryptjs/-/bcryptjs-2.4.3.tgz", mod.PackageDownloadLocation)
			assert.Equal(t, models.HashAlgorithm("SHA256"), mod.CheckSum.Algorithm)
			assert.Equal(t, h, mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2012 Nevins Bartolomeo <nevins.bartolomeo@gmail.com>", strings.TrimSpace(mod.Copyright))
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
	}

	assert.Equal(t, 4, count)
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
