// SPDX-License-Identifier: Apache-2.0

package spack

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"time"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

func (m *spack) convertSpackPackageToModule(specfile string) (models.Module, error) {

	// Prepare a new module from the loaded spec
	module := models.Module{}

	if !helper.Exists(specfile) {
		return module, fmt.Errorf("spec for package does not exist")
	}

	// Open our jsonFile
	spec, err := os.Open(specfile)
	if err != nil {
		return module, err
	}
	defer spec.Close()

	// read our opened xmlFile as a byte array.
	byteValue, err := ioutil.ReadAll(spec)
	if err != nil {
		return module, err
	}

	// Unmarshall into new spack Package
	var pkg SpackPackage
	json.Unmarshal(byteValue, &pkg)

	// Not sure this is even possible, but don't want to make assumptions...
	if len(pkg.Spec.Nodes) == 0 {
		return module, fmt.Errorf("spec for package is missing nodes")
	}

	// The first node is the main package (rest are deps)
	mainPkg := pkg.Spec.Nodes[0]

	// Get and populate the root module
	module = getModule(mainPkg, true)
	module.Path = getInstallPath(specfile)
	module.LocalPath = m.getLocalPath(module.Path)

	// Add dependencies - limited metadata
	for i, node := range pkg.Spec.Nodes {
		if i == 0 {
			continue
		}
		dep := getModule(node, false)
		depName := fmt.Sprintf("%s@%s", dep.Name, dep.Version)
		module.Modules[depName] = &dep
	}
	return module, nil
}

func getModule(pkg Node, isRoot bool) models.Module {

	module := models.Module{}
	module.Modules = make(map[string]*models.Module)
	year, _, _ := time.Now().Date()

	// wrap the checksum
	checksum := models.CheckSum{
		Algorithm: models.HashAlgoSHA256,
		Value:     pkg.PackageHash,
	}
	// Update the module with top level fields
	module.Version = pkg.Version
	module.Copyright = fmt.Sprintf("%d", year)
	module.Name = pkg.Name
	module.Supplier = getPackageSupplier()
	module.PackageURL = fmt.Sprintf("%s/blob/%s/var/spack/repos/builtin/packages/%s/package.py", spackRepo, spackBranch, pkg.Name)
	module.PackageDownloadLocation = ""
	module.CheckSum = &checksum
	module.PackageHomePage = fmt.Sprintf("https://packages.spack.io/package.html?name=%s", pkg.Name)
	if isRoot {
		module.Root = true
	}
	return module
}

// Get a listing of spack packages (modules in spdx)
func (m *spack) getModulesList() ([]models.Module, error) {

	var modules []models.Module

	// This returns .spack paths
	for _, path := range m.getInstallPaths(m.installDir()) {
		spec := filepath.Join(path, m.metadata.Manifest[0])
		module, err := m.convertSpackPackageToModule(spec)
		if err != nil {
			modules = append(modules, module)
		}
	}

	return modules, nil
}

// getPackageSupplier should return information about spack
func getPackageSupplier() models.SupplierContact {
	return models.SupplierContact{
		Name: "Spack Maintainers",
		Type: models.Organization,
	}
}
