// SPDX-License-Identifier: Apache-2.0

package javamaven

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"github.com/vifraa/gopom"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

// RepositoryUrl is the repository url
var RepositoryUrl string = "https://mvnrepository.com/artifact/"

// captures os.Stdout data and writes buffers
func stdOutCapture() func() (string, error) {
	readFromPipe, writeToPipe, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	done := make(chan error, 1)

	save := os.Stdout
	os.Stdout = writeToPipe

	var buffer strings.Builder

	go func() {
		_, err := io.Copy(&buffer, readFromPipe)
		readFromPipe.Close()
		done <- err
	}()

	return func() (string, error) {
		os.Stdout = save
		writeToPipe.Close()
		err := <-done
		return buffer.String(), err
	}
}

func getDependencyList() ([]string, error) {
	done := stdOutCapture()
	var err error

	cmd1 := exec.Command("mvn", "-o", "dependency:list")
	cmd2 := exec.Command("grep", ":.*:.*:.*")
	cmd3 := exec.Command("cut", "-d]", "-f2-")
	cmd4 := exec.Command("sort", "-u")
	cmd2.Stdin, err = cmd1.StdoutPipe()
	cmd3.Stdin, err = cmd2.StdoutPipe()
	cmd4.Stdin, err = cmd3.StdoutPipe()
	cmd4.Stdout = os.Stdout
	err = cmd4.Start()
	err = cmd3.Start()
	err = cmd2.Start()
	err = cmd1.Run()
	err = cmd2.Wait()
	err = cmd3.Wait()
	err = cmd4.Wait()

	capturedOutput, err := done()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	s := strings.Split(capturedOutput, "\n")
	return s, err
}

func updateLicenseInformationToModule(mod *models.Module) {
	licensePkg, err := helper.GetLicenses(".")
	if err == nil {
		mod.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		mod.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		mod.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
		mod.CommentsLicense = licensePkg.Comments
	}
}

// Update package supplier information
func updatePackageSuppier(project gopom.Project, mod *models.Module, developers []gopom.Developer) {
	// By Default set name as project name
	if mod.Root {
		if len(project.Name) > 0 {
			mod.Supplier.Name = project.Name
		} else if len(project.GroupID) > 0 {
			mod.Supplier.Name = project.GroupID
		} else if len(project.ArtifactID) > 0 {
			mod.Supplier.Name = project.ArtifactID
		}

		for _, developer := range developers {
			if len(developer.Name) > 0 && len(developer.Email) > 0 {
				mod.Supplier.Type = models.Person
				mod.Supplier.Name = developer.Name
				mod.Supplier.Email = developer.Email
			} else if len(developer.Email) == 0 && len(developer.Name) > 0 {
				mod.Supplier.Type = models.Person
				mod.Supplier.Name = developer.Name
			}
		}
	} else {
		mod.Supplier.Name = mod.Name
	}
}

// Update package download location
func updatePackageDownloadLocation(groupID string, project gopom.Project, mod *models.Module, distManagement gopom.DistributionManagement) {
	if len(distManagement.DownloadURL) > 0 && (strings.HasPrefix(distManagement.DownloadURL, "http") ||
		strings.HasPrefix(distManagement.DownloadURL, "https")) {
		mod.PackageDownloadLocation = distManagement.DownloadURL
	} else {
		if mod.Root {
			if len(project.URL) > 0 {
				mod.PackageDownloadLocation = project.URL
			} else if len(project.GroupID) > 0 {
				mod.PackageDownloadLocation = RepositoryUrl + project.GroupID
			} else {
				mod.PackageDownloadLocation = RepositoryUrl + project.ArtifactID
			}
		} else {
			mod.PackageDownloadLocation = RepositoryUrl + groupID + "/" + mod.Name + "/" + mod.Version
		}
	}
}

func convertProjectLevelPackageToModule(project gopom.Project) models.Module {
	// package to module
	var modName string
	if len(project.Name) == 0 {
		modName = strings.Replace(strings.TrimSpace(project.ArtifactID), " ", "-", -1)
	} else {
		modName = strings.TrimSpace(project.Name)
		if strings.HasPrefix(modName, "$") {
			name := strings.TrimLeft(strings.TrimRight(modName, "}"), "${")
			if strings.HasPrefix(name, "project.artifactId") {
				modName = project.ArtifactID
			}
		}
		modName = strings.Replace(modName, " ", "-", -1)
	}

	var modVersion string
	if len(project.Version) > 0 {
		modVersion = project.Version
	} else if len(project.Parent.Version) > 0 {
		modVersion = project.Parent.Version
	}
	if strings.HasPrefix(modVersion, "$") {
		version := strings.TrimLeft(strings.TrimRight(modVersion, "}"), "${")
		modVersion = project.Properties.Entries[version]
	}

	var mod models.Module
	mod.Name = modName
	mod.Version = modVersion
	mod.Modules = map[string]*models.Module{}
	mod.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     readCheckSum(modName),
	}
	mod.Root = true
	updatePackageSuppier(project, &mod, project.Developers)
	updatePackageDownloadLocation(project.GroupID, project, &mod, project.DistributionManagement)
	updateLicenseInformationToModule(&mod)
	if len(project.URL) > 0 {
		mod.PackageURL = project.URL
	}

	return mod
}

func findInDependency(slice []gopom.Dependency, val string) bool {
	for _, item := range slice {
		if item.ArtifactID == val {
			return true
		}
	}
	return false
}

func findInPlugins(slice []gopom.Plugin, val string) bool {
	for _, item := range slice {
		if item.ArtifactID == val {
			return true
		}
	}
	return false
}

func createModule(groupID string, name string, version string, project gopom.Project) models.Module {
	var mod models.Module
	modVersion := version
	if strings.HasPrefix(version, "$") {
		version1 := strings.TrimLeft(strings.TrimRight(version, "}"), "${")
		modVersion = project.Properties.Entries[version1]
	}

	name = path.Base(name)
	name = strings.TrimSpace(name)
	mod.Name = strings.Replace(name, " ", "-", -1)
	mod.Version = modVersion
	mod.Modules = map[string]*models.Module{}
	mod.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     readCheckSum(name),
	}
	updatePackageSuppier(project, &mod, project.Developers)
	updatePackageDownloadLocation(groupID, project, &mod, project.DistributionManagement)
	updateLicenseInformationToModule(&mod)
	return mod
}

func readAndLoadPomFile(fpath string) (gopom.Project, error) {
	var project gopom.Project

	filePath := fpath + "/pom.xml"
	pomFile, err := os.Open(filePath)
	if err != nil {
		fmt.Println(err)
		return project, err
	}

	defer func() {
		if pomFile != nil {
			pomFile.Close()
		}
	}()

	// read our opened xmlFile as a byte array.
	pomData, err := ioutil.ReadAll(pomFile)
	if err != nil {
		return project, err
	}

	// Load project from string
	if err := xml.Unmarshal(pomData, &project); err != nil {
		fmt.Printf("unable to unmarshal pom file. Reason: %v", err)
		return project, err
	}

	return project, nil
}

func getModule(modules []models.Module, name string) (models.Module, error) {
	for _, module := range modules {
		if module.Name == name {
			return module, nil
		}
	}
	return models.Module{}, moduleNotFound
}

// If parent pom.xml has modules information in it, go to individual modules pom.xml
func convertPkgModulesToModule(existingModules []models.Module, fpath string, moduleName string, parentPom gopom.Project) ([]models.Module, error) {
	var modules []models.Module
	filePath := fpath + "/" + moduleName
	project, err := readAndLoadPomFile(filePath)
	if err != nil {
		return []models.Module{}, err
	}

	parentMod := convertProjectLevelPackageToModule(project)
	parentMod.Root = false
	modules = append(modules, parentMod)

	// Include dependecy from module pom.xml if it is not existing in ParentPom
	for _, element := range project.Dependencies {
		name := strings.Replace(strings.TrimSpace(element.ArtifactID), " ", "-", -1)
		found1 := false
		found := findInDependency(parentPom.Dependencies, name)
		if !found {
			found1 = findInDependency(parentPom.DependencyManagement.Dependencies, name)
			if !found1 {
				mod := createModule(element.GroupID, name, element.Version, project)
				modules = append(modules, mod)
				parentMod.Modules[mod.Name] = &mod
			}
		}

		if found || found1 {
			module, err := getModule(existingModules, name)
			if err == nil {
				parentMod.Modules[name] = &module
			}
		}
	}

	// Include plugins from module pom.xml if it is not existing in ParentPom
	for _, element := range project.Build.Plugins {
		name := strings.Replace(strings.TrimSpace(element.ArtifactID), " ", "-", -1)
		found1 := false
		found := findInPlugins(parentPom.Build.Plugins, name)
		if !found {
			found1 = findInPlugins(parentPom.Build.PluginManagement.Plugins, name)
			if !found1 {
				mod := createModule(element.GroupID, name, element.Version, project)
				modules = append(modules, mod)
				parentMod.Modules[mod.Name] = &mod
			}
		}

		if found || found1 {
			module, err := getModule(existingModules, name)
			if err == nil {
				parentMod.Modules[name] = &module
			}
		}
	}
	return modules, nil
}

func convertPOMReaderToModules(fpath string, lookForDepenent bool) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	project, err := readAndLoadPomFile(fpath)
	if err != nil {
		return []models.Module{}, err
	}
	parentMod := convertProjectLevelPackageToModule(project)
	parentMod.Root = true
	modules = append(modules, parentMod)

	// iterate over dependencyManagement
	for _, dependencyManagement := range project.DependencyManagement.Dependencies {
		mod := createModule(dependencyManagement.GroupID, dependencyManagement.ArtifactID, dependencyManagement.Version, project)
		modules = append(modules, mod)
		parentMod.Modules[mod.Name] = &mod
	}

	// iterate over dependencies
	for _, dep := range project.Dependencies {
		mod := createModule(dep.GroupID, dep.ArtifactID, dep.Version, project)
		modules = append(modules, mod)
		parentMod.Modules[mod.Name] = &mod
	}

	// iterate over Plugins
	for _, plugin := range project.Build.Plugins {
		// If plugin has groupId, skip here. Plugin details will be available at PluginManagement
		if len(plugin.GroupID) == 0 {
			mod := createModule(plugin.GroupID, plugin.ArtifactID, plugin.Version, project)
			modules = append(modules, mod)
			parentMod.Modules[mod.Name] = &mod
		}
	}

	// iterate over PluginManagement
	for _, plugin := range project.Build.PluginManagement.Plugins {
		mod := createModule(plugin.GroupID, plugin.ArtifactID, plugin.Version, project)
		modules = append(modules, mod)
		parentMod.Modules[mod.Name] = &mod
	}

	dependencyList, err := getDependencyList()
	if err != nil {
		fmt.Println("error in getting mvn dependency list and parsing it")
		return modules, err
	}

	// Add additional dependency from mvn dependency list to pom.xml dependency list
	var i int
	for i < len(dependencyList)-2 { // skip 1 empty line and Finished statement line
		// If any errors captured in mvn dependency, ignore that
		if strings.Contains(dependencyList[i], "Invalid module name") {
			i++
			continue
		}
		dependencyItem := strings.Split(dependencyList[i], ":")[1]

		found := false
		// iterate over dependencies
		for _, dep := range project.Dependencies {
			if dep.ArtifactID == dependencyItem {
				found = true
				break
			}
		}

		if !found {
			for _, dependencyManagement := range project.DependencyManagement.Dependencies {
				if dependencyManagement.ArtifactID == dependencyItem {
					found = true
					break
				}
			}
		}

		if !found {
			groupID := strings.Split(dependencyList[i], ":")[0]
			version := strings.Split(dependencyList[i], ":")[3]
			mod := createModule(strings.TrimSpace(groupID), dependencyItem, version, project)
			modules = append(modules, mod)
			parentMod.Modules[mod.Name] = &mod
		}
		i++
	}

	if lookForDepenent {
		// iterate over Modules
		for _, module := range project.Modules {
			additionalModules, err := convertPkgModulesToModule(modules, fpath, module, project)
			if err != nil {
				// continue reading other module pom.xml file
				continue
			}
			modules = append(modules, additionalModules...)
		}
	}
	return modules, nil
}

func getTransitiveDependencyList(workingDir string) (map[string][]string, error) {
	path := filepath.Join(os.TempDir(), "JavaMavenTDTreeOutput.txt")
	os.Remove(path)

	command := exec.Command("mvn", "dependency:tree", "-DoutputType=dot", "-DappendOutput=true", "-DoutputFile="+path)
	command.Dir = workingDir
	out, err := command.CombinedOutput()
	if err != nil {
		log.Print(string(out))
		return nil, err
	}

	tdList, err := readAndgetTransitiveDependencyList(path)
	if err != nil {
		return nil, err
	}
	return tdList, nil
}

func readAndgetTransitiveDependencyList(path string) (map[string][]string, error) {

	file, err := os.Open(path)

	if err != nil {
		log.Println(err)
		return nil, err
	}

	scanner := bufio.NewScanner(file)

	scanner.Split(bufio.ScanLines)
	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	file.Close()

	tdList := map[string][]string{}
	handlePkgs(text, tdList)
	return tdList, nil
}

func doesDependencyExists(tdList map[string][]string, lData string, val string) bool {
	for _, item := range tdList[lData] {
		if item == val {
			return true
		}
	}
	return false
}

func handlePkgs(text []string, tdList map[string][]string) {
	i := 0
	var pkgName string
	isEmptyMainPkg := false

	for i < len(text) {
		if strings.Contains(text[i], "{") {
			pkgName = strings.Split(text[i], ":")[1]
		} else if strings.Contains(text[i], "->") {
			lhsData := strings.Split(text[i], "->")[0]
			rhsData := strings.Split(text[i], "->")[1]
			lData := strings.Split(lhsData, ":")[1]
			rData := strings.Split(rhsData, ":")[1]

			// If package name is same, add right hand side dependency
			if !isEmptyMainPkg && lData == pkgName {
				tdList[pkgName] = append(tdList[pkgName], rData)
			} else if !doesDependencyExists(tdList, lData, rData) { // check whether dependency already exists
				tdList[lData] = append(tdList[lData], rData)
			}
		} else if strings.Contains(text[i], "}") {
			if i == 1 {
				isEmptyMainPkg = true
			}
		}
		i++
	}
}

func buildDependenciesGraph(modules []models.Module, tdList map[string][]string) {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}

	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
	}

	for i := range tdList {
		for j := range tdList[i] {

			if len(tdList[i][j]) > 0 {
				moduleName := i
				if _, ok := moduleMap[moduleName]; !ok {
					continue
				}

				depName := tdList[i][j]
				depModule, ok := moduleMap[depName]
				if !ok {
					continue
				}

				modules[moduleIndex[moduleName]].Modules[depName] = &models.Module{
					Name:                    depModule.Name,
					Version:                 depModule.Version,
					Path:                    depModule.Path,
					LocalPath:               depModule.LocalPath,
					Supplier:                depModule.Supplier,
					PackageURL:              depModule.PackageURL,
					CheckSum:                depModule.CheckSum,
					PackageHomePage:         depModule.PackageHomePage,
					PackageDownloadLocation: depModule.PackageDownloadLocation,
					LicenseConcluded:        depModule.LicenseConcluded,
					LicenseDeclared:         depModule.LicenseDeclared,
					CommentsLicense:         depModule.CommentsLicense,
					OtherLicense:            depModule.OtherLicense,
					Copyright:               depModule.Copyright,
					PackageComment:          depModule.PackageComment,
					Root:                    depModule.Root,
				}
			}
		}
	}
}
