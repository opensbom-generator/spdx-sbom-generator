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
	"spdx-sbom-generator/internal/licenses"
	"spdx-sbom-generator/internal/models"
	"strings"
)

// Update package supplier information
func updatePackageSuppier(mod models.Module, developer Developer) {
	if len(developer.Name) > 0 && len(developer.Email) > 0 {
		mod.Supplier.Type = "Person"
		mod.Supplier.Name = developer.Name
		mod.Supplier.Email = developer.Email
	} else if len(developer.Email) == 0 && len(developer.Name) > 0 {
		mod.Supplier.Type = "Person"
		mod.Supplier.Name = developer.Name
	}

	// check for organization tag
	if len(developer.Organization) > 0 {
		mod.Supplier.Type = "Organization"
	}
}

// Update package download location
func updatePackageDownloadLocation(mod models.Module, distManagement DistributionManagement) {
	if len(distManagement.DownloadUrl) > 0 && (strings.HasPrefix(distManagement.DownloadUrl, "http") ||
		strings.HasPrefix(distManagement.DownloadUrl, "https")) {
		// ******** TODO Module has only PackageHomePage, it does not have PackageDownloadLocation field
		//mod.PackageHomePage = distManagement.DownloadUrl
	}
}

// captures os.Stdout data and writes buffers
func stdOutCapture() func() (string, error) {
	read, write, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	done := make(chan error, 1)

	save := os.Stdout
	os.Stdout = write

	var buf strings.Builder

	go func() {
		_, err := io.Copy(&buf, read)
		read.Close()
		done <- err
	}()

	return func() (string, error) {
		os.Stdout = save
		write.Close()
		err := <-done
		return buf.String(), err
	}
}

func getDependencyList() ([]string, error) {
	done := stdOutCapture()

	// TODO add error handling
	c1 := exec.Command("mvn", "-o", "dependency:list")
	c2 := exec.Command("grep", ":.*:.*:.*")
	c3 := exec.Command("cut", "-d]", "-f2-")
	c4 := exec.Command("sort", "-u")
	c2.Stdin, _ = c1.StdoutPipe()
	c3.Stdin, _ = c2.StdoutPipe()
	c4.Stdin, _ = c3.StdoutPipe()
	c4.Stdout = os.Stdout
	_ = c4.Start()
	_ = c3.Start()
	_ = c2.Start()
	_ = c1.Run()
	_ = c2.Wait()
	_ = c3.Wait()
	_ = c4.Wait()

	capturedOutput, err := done()
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	s := strings.Split(capturedOutput, "\n")
	return s, err
}

func convertPOMReaderToModules() ([]models.Module, error) {
	modules := make([]models.Module, 0)

	pomFile, err := os.Open("pom.xml")
	if err != nil {
		fmt.Println(err)
		return modules, err
	}
	defer pomFile.Close()

	// read our opened xmlFile as a byte array.
	pomStr, _ := ioutil.ReadAll(pomFile)

	// Load project from string
	var project MavenPomProject
	if err := xml.Unmarshal([]byte(pomStr), &project); err != nil {
		log.Println("unable to unmarshal pom file. Reason: %s", err)
		return modules, err
	}

	dependencyList, err := getDependencyList()
	if err != nil {
		fmt.Println("error in getting mvn dependency list and parsing it")
		return modules, err
	}

	var licenseInfomation string
	// ***** TODO Code works for handling multiple license tag, but restricted it for single license tag
	if len(project.Licenses) == 1 {
		for i, license := range project.Licenses {
			for key, x := range licenses.DB {
				if x == license.Name {
					licenseID := key
					if i == 0 {
						licenseInfomation = licenseID
					} else {
						licenseInfomation = licenseInfomation + " AND " + licenseID
					}
				}
			}
		}
	}

	var mod models.Module
	if len(project.Name) == 0 {
		mod.Name = strings.Replace(project.ArtifactId, " ", "-", -1)
	} else {
		mod.Name = strings.Replace(project.Name, " ", "-", -1)
	}
	mod.Version = project.Version
	mod.Root = true
	updatePackageSuppier(mod, project.Developers)
	updatePackageDownloadLocation(mod, project.DistributionManagement)
	mod.LicenseDeclared = licenseInfomation
	mod.LicenseConcluded = mod.LicenseDeclared
	if len(project.Url) > 0 {
		mod.PackageHomePage = project.Url
	}
	mod.Modules = map[string]*models.Module{}
	mod.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     readCheckSum(mod.Path),
	}

	modules = append(modules, mod)

	// iterate over Modules
	for _, module := range project.Modules {
		var mod models.Module
		mod.Name = module
		mod.Modules = map[string]*models.Module{}
		// set package version as module version
		mod.Version = project.Version
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(module),
		}
		modules = append(modules, mod)
	}

	// iterate over dependencies
	for _, dependencyManagement := range project.DependencyManagement.Dependencies {
		var mod models.Module
		mod.Name = path.Base(dependencyManagement.ArtifactId)
		if len(project.Properties) > 0 {
			version := strings.TrimLeft(strings.TrimRight(dependencyManagement.Version, "}"), "${")
			mod.Version = project.Properties[version]
		}
		mod.Modules = map[string]*models.Module{}
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(dependencyManagement.ArtifactId),
		}
		modules = append(modules, mod)
	}

	// iterate over dependencies
	for _, dep := range project.Dependencies {
		var mod models.Module
		mod.Name = path.Base(dep.ArtifactId)
		mod.Version = dep.Version
		mod.Modules = map[string]*models.Module{}
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(dep.ArtifactId),
		}
		modules = append(modules, mod)
	}

	// Add additional dependency from mvn dependency list to pom.xml dependency list
	var i int
	for i < len(dependencyList)-2 { // skip 1 empty line and Finished statement line
		dependencyItem := strings.Split(dependencyList[i], ":")[1]

		found := false
		// iterate over dependencies
		for _, dep := range project.Dependencies {
			if dep.ArtifactId == dependencyItem {
				found = true
				break
			}
		}

		if !found {
			for _, dependencyManagement := range project.DependencyManagement.Dependencies {
				if dependencyManagement.ArtifactId == dependencyItem {
					found = true
					break
				}
			}
		}

		if !found {
			var mod models.Module
			mod.Name = path.Base(dependencyItem)
			mod.Version = strings.Split(dependencyList[i], ":")[3]
			mod.Modules = map[string]*models.Module{}
			mod.CheckSum = &models.CheckSum{
				Algorithm: models.HashAlgoSHA1,
				Value:     readCheckSum(dependencyItem),
			}
			modules = append(modules, mod)
		}
		i++
	}

	// iterate over Plugins
	for _, plugin := range project.Build.Plugins {
		var mod models.Module
		mod.Name = path.Base(plugin.ArtifactId)
		mod.Version = plugin.Version
		mod.Modules = map[string]*models.Module{}
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(plugin.ArtifactId),
		}
		modules = append(modules, mod)
	}

	return modules, nil
}

func getTransitiveDependencyList() (map[string][]string, error) {
	path := "/tmp/JavaMavenTDListOutput.txt"
	os.Remove(path)

	command := exec.Command("mvn", "dependency:tree", "-DappendOutput=true", "-DoutputFile=/tmp/JavaMavenTDListOutput.txt")
	_, err := command.Output()
	if err != nil {
		return nil, err
	}

	tdList, err1 := readAndgetTransitiveDependencyList()
	if err1 != nil {
		return nil, err1
	}
	return tdList, nil
}

func readAndgetTransitiveDependencyList() (map[string][]string, error) {

	file, err := os.Open("/tmp/JavaMavenTDListOutput.txt")

	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	scanner := bufio.NewScanner(file)

	scanner.Split(bufio.ScanLines)
	var text []string

	for scanner.Scan() {
		text = append(text, scanner.Text())
	}
	file.Close()

	j := 0
	tdList := map[string][]string{}

	for j < len(text) {
		_, isTrue := isSubPackage(text[j])
		if !isTrue {
			dependencyItem := strings.Split(text[j], ":")[1]
			pkgName := dependencyItem

			val := handlePkg(text[j+1:], tdList, pkgName)
			if val == -1 {
				break
			}
			j = j + val
		}
		j++
	}
	return tdList, nil
}

func handlePkg(text []string, tdList map[string][]string, pkgName string) int {
	i := 0
	cnt := 0
	newSubPkgCnt := 0
	subPkgs := make([]string, 5)
	subLevelPkgs := make([]string, 5)
	currentTextVal := pkgName
	var subpkg string

	for i < len(text) {
		dependencyItem := strings.Split(text[i], ":")[1]
		subpkg = dependencyItem

		level, isTrue := isSubPackage(text[i])

		if !isTrue {
			return i
		} else {
			if level == 1 {
				subPkgs[cnt] = subpkg
				tdList[pkgName] = subPkgs
				cnt++
			} else if level == 2 {
				subLevelPkgs[newSubPkgCnt] = subpkg
				tdList[currentTextVal] = subLevelPkgs
				newSubPkgCnt++
			}
		}
		// store previous line item
		currentTextVal = subpkg
		i++
	}
	return -1
}

func isSubPackage(name string) (int, bool) {
	if strings.HasPrefix(name, "\\-") || strings.HasPrefix(name, "+-") {
		return 1, true
	} else if strings.Contains(name, "   \\-") || strings.Contains(name, "|  \\- ") {
		return 2, true
	}
	return 0, false
}

func buildDependenciesGraph(modules []models.Module, tdList map[string][]string) error {
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
					Name:             depModule.Name,
					Version:          depModule.Version,
					Path:             depModule.Path,
					LocalPath:        depModule.LocalPath,
					Supplier:         depModule.Supplier,
					PackageURL:       depModule.PackageURL,
					CheckSum:         depModule.CheckSum,
					PackageHomePage:  depModule.PackageHomePage,
					LicenseConcluded: depModule.LicenseConcluded,
					LicenseDeclared:  depModule.LicenseDeclared,
					CommentsLicense:  depModule.CommentsLicense,
					OtherLicense:     depModule.OtherLicense,
					Copyright:        depModule.Copyright,
					PackageComment:   depModule.PackageComment,
					Root:             depModule.Root,
				}
			}
		}
	}

	return nil
}
