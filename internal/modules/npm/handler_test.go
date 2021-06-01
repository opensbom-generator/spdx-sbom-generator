package npm

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os/exec"
	"spdx-sbom-generator/internal/models"
	"strings"
	"testing"
)

func TestProcessNPM(t *testing.T) {
	t.Run("test is valid", TestNpm_IsValid)
	t.Run("test has modules installed", TestNpm_HasModulesInstalled)
	t.Run("test get module", TestNpm_GetModule)
	t.Run("test list modules", TestNpm_ListModules)
	t.Run("test list all modules", TestNpm_ListAllModules)
}

func TestNpm_IsValid(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	valid := n.IsValid(path)
	invalid := n.IsValid(getPath())

	// Assert
	assert.Equal(t, true, valid)
	assert.Equal(t, false, invalid)
}

func TestNpm_HasModulesInstalled(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	installed := n.HasModulesInstalled(path)
	assert.NoError(t, installed)
	uninstalled := n.HasModulesInstalled(getPath())
	assert.Error(t, uninstalled)
}

func TestNpm_GetModule(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.GetModule(path)

	assert.NoError(t, err)
	assert.Equal(t, "e-commerce", mods[0].Name)
	assert.Equal(t, "ahmed saber", mods[0].Supplier.Name)
	assert.Equal(t, "1.0.0", mods[0].Version)

}

func TestNpm_ListModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListModules(path)

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

func TestNpm_ListAllModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListAllModules(path)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {
		if mod.Name == "validator-10.11.0" {
			assert.Equal(t, "10.11.0", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/validator/-/validator-10.11.0.tgz", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha512"), mod.CheckSum.Algorithm)
			assert.Equal(t, "X/p3UZerAIsbBfN/IwahhYaBbY68EN/UQBWHtsbXGT5bfrH/p4NQzUCG1kF/rtKaNpnJ7jAu6NGTdSNtyNIXMw==", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2018 Chris O'Hara <cohara87@gmail.com>", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "shortid-2.2.16" {
			assert.Equal(t, "2.2.16", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/shortid/-/shortid-2.2.16.tgz", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha512"), mod.CheckSum.Algorithm)
			assert.Equal(t, "Ugt+GIZqvGXCIItnsL+lvFJOiN7RYqlGy7QE41O3YC1xbNSeDGIRO7xg2JJXIAj1cAGnOeC1r7/T9pgrtQbv4g==", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) Dylan Greene", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "body-parser-1.19.0" {
			assert.Equal(t, "1.19.0", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/body-parser/-/body-parser-1.19.0.tgz", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha512"), mod.CheckSum.Algorithm)
			assert.Equal(t, "dhEPs72UPbDnAQJ9ZKMNTP6ptJaionhP5cBb541nXPlW60Jepo9RV/a4fX4XWW9CuFNK22krhrj1+rgzifNCsw==", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2014 Jonathan Ong <me@jongleberry.com>", mod.Copyright)
			assert.Equal(t, "MIT", mod.LicenseDeclared)
			count++
			continue
		}
		if mod.Name == "bcryptjs-2.4.3" {
			assert.Equal(t, "2.4.3", mod.Version)
			assert.Equal(t, "https://registry.npmjs.org/bcryptjs/-/bcryptjs-2.4.3.tgz", mod.PackageURL)
			assert.Equal(t, models.HashAlgorithm("sha1"), mod.CheckSum.Algorithm)
			assert.Equal(t, "mrVie5PmBiH/fNrF2pczAn3x0Ms=", mod.CheckSum.Value)
			assert.Equal(t, "Copyright (c) 2012 Nevins Bartolomeo <nevins.bartolomeo@gmail.com>", mod.Copyright)
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
