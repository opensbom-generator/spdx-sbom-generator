// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"encoding/json"
	"encoding/xml"
	"fmt"
	"io/ioutil"
	"os"
	"path/filepath"
	"strings"

	log "github.com/sirupsen/logrus"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

type nuget struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

var (
	packageCachePaths      []string
	dotnetCmd              = "dotnet"
	specExt                = ".nuspec"
	pkgExt                 = ".nupkg"
	sha512Ext              = ".nupkg.sha512"
	nugetBaseUrl           = "https://api.nuget.org/v3-flatcontainer/"
	manifestExtensions     = []string{".sln", ".csproj", ".vbproj"}
	directoryFilterPattern = "*.[^d-u][^c-r]proj"
	assetDirectoryJoinPath = "obj"
	assetModuleFile        = "project.assets.json"
	assetTargets           = "targets"
	assetType              = "type"
	assetPackage           = "package"
	assetDependencies      = "dependencies"
	configModuleFile       = "packages.config"
	nugetPackageSplit      = "global-packages:"
)

// New ...
func New() *nuget {
	return &nuget{
		metadata: models.PluginMetadata{
			Name:       "Nuget Package Manager",
			Slug:       "nuget",
			Manifest:   manifestExtensions,
			ModulePath: []string{},
		},
	}
}

// GetMetadata ...
func (m *nuget) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// SetRootModule ...
func (m *nuget) SetRootModule(path string) error {
	module, err := m.GetRootModule(path)
	if err != nil {
		return err
	}

	m.rootModule = module
	return nil
}

// IsValid ...
func (m *nuget) IsValid(path string) bool {
	projectPath := m.GetProjectManifestPath(path)
	return helper.Exists(projectPath)
}

// HasModulesInstalled ...
func (m *nuget) HasModulesInstalled(path string) error {
	// TODO: check nuGetFallBackFolderPath cache
	if err := m.buildCmd(LocalPackageCacheCmd, "."); err != nil {
		return err
	}
	globalPackageCachePath, err := m.command.Output()
	if err != nil {
		return err
	}

	if globalPackageCachePath == "" {
		return errNoDependencyCache
	}
	cachePathArray := strings.Split(globalPackageCachePath, nugetPackageSplit)
	if len(cachePathArray) > 1 {
		packageCachePaths = append(packageCachePaths, strings.TrimSpace(cachePathArray[1]))
	}

	projectPath := m.GetProjectManifestPath(path)
	log.Infof("trying to restore the packages: %s", projectPath)

	restoreCommand := command(fmt.Sprintf("%s %s", RestorePackageCmd, projectPath))
	if err := m.buildCmd(restoreCommand, "."); err != nil {
		return err
	}

	_, err = m.command.Output()
	if err != nil {
		return err
	}

	log.Infof("looking for the project modules using location: %s", projectPath)

	projectPaths, err := getProjectPaths(projectPath)
	if err != nil {
		return err
	}
	// no projects found
	if len(projectPaths) == 0 {
		return errDependenciesNotFound
	}
	projectArray := []string{}
	// check asset path exists
	modulePath := filepath.Join(assetDirectoryJoinPath, assetModuleFile)
	for _, project := range projectPaths {
		projectDirectory := filepath.Dir(project)
		if helper.Exists(filepath.Join(projectDirectory, modulePath)) {
			// check asset path exists
			continue
		} else if helper.Exists(filepath.Join(projectDirectory, configModuleFile)) {
			// check config path exists
			continue
		}
		projectArray = append(projectArray, project)
	}
	if len(projectArray) == 0 {
		return nil
	}
	log.Infof("no modules found for project:%s", projectArray)
	return errDependenciesNotFound
}

// GetVersion...
func (m *nuget) GetVersion() (string, error) {
	if err := m.buildCmd(VersionCmd, "."); err != nil {
		return "", err
	}

	return m.command.Output()
}

// GetRootModule...
func (m *nuget) GetRootModule(path string) (*models.Module, error) {
	if m.rootModule == nil {
		module := models.Module{}
		projectPath := m.GetProjectManifestPath(path)
		pathExtension := filepath.Ext(projectPath)
		if helper.Exists(projectPath) {
			fileName := filepath.Base(projectPath)
			rootProjectName := fileName[0 : len(fileName)-len(pathExtension)]
			module.Name = rootProjectName
			module.Root = true
			module.CheckSum = &models.CheckSum{
				Algorithm: models.HashAlgoSHA256,
				Content:   []byte(fmt.Sprintf("%s%s", module.Name, module.Version)),
			}
			module.Supplier.Name = rootProjectName
			module.PackageDownloadLocation = buildRootPackageURL(path)
		}
		m.rootModule = &module
	}
	return m.rootModule, nil
}

// ListModulesWithDeps ...
func (m *nuget) ListModulesWithDeps(path string) ([]models.Module, error) {
	var modules []models.Module
	projectPath := m.GetProjectManifestPath(path)
	projectPaths, err := getProjectPaths(projectPath)
	if err != nil {
		return modules, err
	}
	// no projects found
	if len(projectPaths) == 0 {
		return modules, errDependenciesNotFound
	}
	modulePath := filepath.Join(assetDirectoryJoinPath, assetModuleFile)
	for _, project := range projectPaths {
		projectDirectory := filepath.Dir(project)
		if helper.Exists(filepath.Join(projectDirectory, modulePath)) {
			packages, err := m.parseAssetModules(filepath.Join(projectDirectory, modulePath))
			if err != nil {
				return modules, err
			}
			modules = append(modules, packages...)
			log.Infof("dependency tree completed for project(a): %s", project)
		} else if helper.Exists(filepath.Join(projectDirectory, configModuleFile)) {
			packages, err := m.parsePackagesConfigModules(filepath.Join(projectDirectory, configModuleFile))
			if err != nil {
				return modules, err
			}
			log.Infof("dependency tree completed for project(c): %s", project)
			modules = append(modules, packages...)
		}
	}
	if len(modules) == 0 {
		return modules, errFailedToConvertModules
	}
	// set root module
	if m.rootModule != nil {
		modules = append(modules, *m.rootModule)
	}
	return modules, nil
}

// ListUsedModules ...
func (m *nuget) ListUsedModules(path string) ([]models.Module, error) {
	return m.ListModulesWithDeps(path)
}

func (m *nuget) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if cmdArgs[0] != dotnetCmd {
		return errNoDotnetCommand
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}

// GetProjectManifestPath ...
func (m *nuget) GetProjectManifestPath(path string) string {
	for i := range m.metadata.Manifest {
		pathPattern := filepath.Join(path, fmt.Sprintf("*%s", m.metadata.Manifest[i]))
		projectPaths, err := filepath.Glob(pathPattern)
		if err != nil {
			log.Error(err)
		}
		if len(projectPaths) > 0 {
			return projectPaths[0]
		}
		if strings.ToLower(filepath.Ext(path)) == m.metadata.Manifest[i] {
			return path
		}
	}
	return ""
}

// parsePackagesConfigModules parses the output -- works for the packages.config
func (m *nuget) parsePackagesConfigModules(modulePath string) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	raw, err := ioutil.ReadFile(modulePath)
	if err != nil {
		return modules, err
	}
	moduleData := PackageConfig{}
	err = xml.Unmarshal(raw, &moduleData)
	if err != nil {
		return modules, err
	}
	for _, modulePackage := range moduleData.Packages {
		module, err := m.buildModule(modulePackage.ID, modulePackage.Version, nil)
		if err != nil {
			return modules, err
		}
		modules = append(modules, module)
	}
	return modules, nil
}

// parseAssetModules parses the output -- works for the project.assets.json
func (m *nuget) parseAssetModules(modulePath string) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	raw, err := ioutil.ReadFile(modulePath)
	if err != nil {
		return modules, err
	}

	moduleData := map[string]interface{}{}
	err = json.Unmarshal(raw, &moduleData)
	if err != nil {
		return modules, err
	}
	// parse targets from the asset json
	targetsData := moduleData[assetTargets].(map[string]interface{})
	packageNameMap := map[string]string{}
	for _, packageData := range targetsData {
		data := packageData.(map[string]interface{})
		for name, info := range data {
			// split the package name and version
			packageArray := strings.Split(name, "/")
			packageInfo := info.(map[string]interface{})
			// consider only the package type for building the dependencies
			if packageInfo != nil &&
				packageInfo[assetType] == assetPackage && len(packageArray) == 2 {
				packageInfo := info.(map[string]interface{})
				packageName := packageArray[0]
				packageVersion := packageArray[1]
				dependencies := map[string]string{}
				// get the dependency packages
				dependencyModules := packageInfo[assetDependencies]
				if dependencyModules != nil {
					dependencyPackages := dependencyModules.(map[string]interface{})
					for dName, dInfo := range dependencyPackages {
						dVersion, ok := dInfo.(string)
						if ok {
							dUniqueName := fmt.Sprintf("%s-%s", dName, dVersion)
							if _, ok := packageNameMap[dUniqueName]; ok {
								dependencies[dName] = dVersion
							}
						}
					}
				}
				packageUniqueName := fmt.Sprintf("%s-%s", packageName, packageVersion)
				if _, ok := packageNameMap[packageUniqueName]; !ok {
					module, err := m.buildModule(packageName, packageVersion, dependencies)
					if err != nil {
						return modules, err
					}
					modules = append(modules, module)
				}
				packageNameMap[packageUniqueName] = packageVersion
			}
		}
	}
	return modules, nil
}

// getProjectPaths
func getProjectPaths(path string) ([]string, error) {
	var projectPath []string
	directoryPath := filepath.Dir(path)
	err := filepath.Walk(directoryPath, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		if matched, err := filepath.Match(directoryFilterPattern, filepath.Base(path)); err != nil {
			return err
		} else if matched {
			projectPath = append(projectPath, path)
		}
		return nil
	})
	if err != nil {
		return projectPath, err
	}
	return projectPath, nil
}

// buildModule .. set the properties
func (m *nuget) buildModule(name string, version string, dependencies map[string]string) (models.Module, error) {
	var module models.Module
	module.Name = name
	module.Version = version
	//get the hash checksum
	checkSum, err := getHashCheckSum(name, version)
	if err != nil {
		return module, err
	}
	module.CheckSum = checkSum
	// get nuget spec file details
	nuSpecFile, err := getNugetSpec(name, version)
	if err != nil {
		return module, err
	}
	if nuSpecFile != nil {
		if nuSpecFile.Meta.ProjectURL != "" {
			module.PackageURL = nuSpecFile.Meta.ProjectURL
		}
		if helper.LicenseSPDXExists(nuSpecFile.Meta.License) {
			module.LicenseDeclared = helper.BuildLicenseDeclared(nuSpecFile.Meta.License)
			module.LicenseConcluded = helper.BuildLicenseConcluded(nuSpecFile.Meta.License)
		} else if nuSpecFile.Meta.License != "" {
			module.LicenseDeclared = extractLicence(nuSpecFile.Meta.License)
			module.LicenseConcluded = extractLicence(nuSpecFile.Meta.License)
		}
		module.Copyright = nuSpecFile.Meta.Copyright
		if nuSpecFile.Meta.Authors != "" {
			module.Supplier.Name = nuSpecFile.Meta.Authors
		} else if nuSpecFile.Meta.Owners != "" {
			module.Supplier.Name = nuSpecFile.Meta.Owners
		} else {
			module.Supplier.Name = m.rootModule.Supplier.Name
		}
		if nuSpecFile.Meta.Repository.URL != "" {
			module.PackageDownloadLocation = buildDownloadURL(nuSpecFile.Meta.Repository.URL)
		} else {
			module.PackageDownloadLocation = m.rootModule.PackageDownloadLocation
		}
	}
	// set dependencies
	dependencyModules := map[string]*models.Module{}
	for dName, dVersion := range dependencies {
		checkSum, err := getHashCheckSum(name, version)
		if err != nil {
			return module, err
		}
		dependencyModules[dName] = &models.Module{
			Name:     dName,
			Version:  dVersion,
			CheckSum: checkSum,
		}
	}
	module.Modules = dependencyModules
	return module, nil
}

// getCachedSpecFilename
func getCachedSpecFilename(name string, version string) string {
	var specFilename string
	if name == "" || version == "" {
		return specFilename
	}
	name = strings.ToLower(name)
	for _, path := range packageCachePaths {
		var directory = filepath.Join(path, name, version)
		var fileName = filepath.Join(directory, fmt.Sprintf("%s%s", name, specExt))
		if helper.Exists(fileName) {
			specFilename = fileName
			break
		}
	}
	return specFilename
}

// getNugetSpec ...
func getNugetSpec(name string, version string) (*NugetSpec, error) {
	nuSpecFile := NugetSpec{}
	specFileName := getCachedSpecFilename(name, version)
	if specFileName != "" {
		raw, err := ioutil.ReadFile(specFileName)
		if err != nil {
			return nil, err
		}
		specFile, err := ConvertFromBytes(raw)
		if err != nil {
			return nil, err
		}
		return specFile, nil
	}
	nugetUrlPrefix := fmt.Sprintf("%s%s/%s/%s", nugetBaseUrl, name, version, name)
	nuspecUrl := fmt.Sprintf("%s%s", nugetUrlPrefix, specExt)
	resp, err := getHttpResponseWithHeaders(nuspecUrl, map[string]string{"content-type": "application/xml"})
	if err != nil {
		return nil, err
	}

	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			log.Error(fmt.Sprintf("%#v", err))
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	err = xml.Unmarshal(body, &nuSpecFile)
	if err != nil {
		return nil, err
	}
	return &nuSpecFile, nil
}

// getHashCheckSum ...
func getHashCheckSum(name string, version string) (*models.CheckSum, error) {
	var fileData []byte
	specFileName := getCachedSpecFilename(name, version)
	if specFileName != "" {
		extension := filepath.Ext(specFileName)
		// extract the file name
		fileName := specFileName[0 : len(specFileName)-len(extension)]
		// change the extension - sha512Ext
		shaName := fmt.Sprintf("%s.%s%s", fileName, version, sha512Ext)
		// change the extension - pkgExt
		pkgName := fileName + fmt.Sprintf("%s.%s%s", fileName, version, pkgExt)
		if helper.Exists(shaName) {
			shaFileData, err := ioutil.ReadFile(shaName)
			if err != nil {
				return nil, err
			}
			fileData = shaFileData
		} else if helper.Exists(pkgName) {
			shaFileData, err := ioutil.ReadFile(pkgName)
			if err != nil {
				return nil, err
			}
			fileData = shaFileData
		}
	}
	if fileData != nil {
		return &models.CheckSum{
			Algorithm: models.HashAlgoSHA256,
			Content:   fileData,
		}, nil
	}
	nugetUrlPrefix := fmt.Sprintf("%s%s/%s/%s", nugetBaseUrl, name, version, name)
	nuPkgUrl := fmt.Sprintf("%s.%s%s", nugetUrlPrefix, version, pkgExt)
	resp, err := getHttpResponseWithHeaders(nuPkgUrl, map[string]string{"content-type": "application/xml"})
	if err != nil {
		return nil, err
	}
	defer func() {
		closeErr := resp.Body.Close()
		if closeErr != nil {
			log.Error(fmt.Sprintf("%#v", err))
		}
	}()

	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}
	if body != nil {
		return &models.CheckSum{
			Algorithm: models.HashAlgoSHA256,
			Content:   fileData,
		}, nil
	}
	return nil, nil
}

// extractLicence from the licenceMetaData
func extractLicence(licenceMetaData string) string {
	licenseArray := strings.Split(licenceMetaData, " ")
	for _, license := range licenseArray {
		if helper.LicenseSPDXExists(license) {
			return license
		}
	}
	return ""
}
