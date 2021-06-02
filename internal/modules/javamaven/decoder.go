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
	//log.Println(" ****** developer.Name: "+developer.Name+" developer.Email: "+developer.Email+"  developer.Organization: ", developer.Organization)
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
	//log.Println(" ****** distManagement.DownloadUrl: ", distManagement.DownloadUrl)
	if len(distManagement.DownloadUrl) > 0 && (strings.HasPrefix(distManagement.DownloadUrl, "http") ||
		strings.HasPrefix(distManagement.DownloadUrl, "https")) {
		mod.PackageHomePage = distManagement.DownloadUrl
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

	//log.Println("***** capturedOutput: \n", capturedOutput)
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

	//log.Println(" ***** len(project.Licenses): ", len(project.Licenses))

	var licenseInfomation string
	// Print License information
	for i, license := range project.Licenses {
		//log.Println(" license.name", license.Name)
		for key, x := range licenses.DB {

			if x == license.Name {
				licenseID := key
				//log.Println("  licenseID: " + licenseID)
				if i == 0 {
					licenseInfomation = licenseInfomation + licenseID
				} else {
					licenseInfomation = licenseInfomation + " AND " + licenseID
				}
			}
		}
	}

	//log.Println(" ****** licenseInfomation: ", licenseInfomation)
	var mod models.Module
	if len(project.Name) == 0 {
		mod.Name = project.ArtifactId
	} else {
		mod.Name = project.Name
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
		//log.Println("	1111111111 module: ", module)
		var mod models.Module
		mod.Name = module
		mod.Modules = map[string]*models.Module{}
		//mod.Version = modules.Version
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(module),
		}
		modules = append(modules, mod)
	}

	// iterate over dependencies
	for _, dependencyManagement := range project.DependencyManagement.Dependencies {
		//log.Println("	2222222222 dependencyManagement.ArtifactId: ", dependencyManagement.ArtifactId)
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
		//log.Println("	333333333 dep.ArtifactId: ", dep.ArtifactId)
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

	//	fmt.Println(" ******* len(dependencyList): ", len(dependencyList))
	// Add additional dependency from mvn dependency list to pom.xml dependency list
	var i int
	for i < len(dependencyList)-2 { // skip 1 empty line and Finished statement line
		//fmt.Println(dependencyList[i])
		dependencyItem := strings.Split(dependencyList[i], ":")[1]

		found := false
		// iterate over dependencies
		for _, dep := range project.Dependencies {
			if dep.ArtifactId == dependencyItem {
				//log.Println("dependency " + dependencyItem + ":" + strings.Split(dependencyList[i], ":")[3] + " already exists")
				found = true
				break
			}
		}

		if !found {
			for _, dependencyManagement := range project.DependencyManagement.Dependencies {
				//fmt.Println(" dependencyManagement.ArtifactId", dependencyManagement.ArtifactId)
				if dependencyManagement.ArtifactId == dependencyItem {
					//log.Println("dependency " + dependencyItem + ":" + strings.Split(dependencyList[i], ":")[3] + " already exists")
					found = true
					break
				}
			}
		}

		if !found {
			var mod models.Module
			mod.Name = path.Base(dependencyItem)
			mod.Version = strings.Split(dependencyList[i], ":")[3]
			//log.Println("	**** Adding dependency: " + strings.Split(dependencyList[i], ":")[1] + ":" + strings.Split(dependencyList[i], ":")[3])
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
	// TODO Remove hardcoded file path
	command := exec.Command("mvn", "dependency:tree", "-DappendOutput=true", "-DoutputFile=/tmp/TodayOutput.txt")
	_, err := command.Output()
	if err != nil {
		return nil, err
	}
	//	fmt.Printf("%s", output)

	tdList, err1 := readAndgetTransitiveDependencyList()
	if err1 != nil {
		return nil, err1
	}
	return tdList, nil
}

func readAndgetTransitiveDependencyList() (map[string][]string, error) {

	file, err := os.Open("/tmp/TodayOutput.txt")

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
		if !isSubPackage(text[j]) {
			//log.Println("line number "+strconv.Itoa(j)+" PKG Name:", text[j])
			dependencyItem := strings.Split(text[j], ":")[1]
			//log.Println("				PKG " + dependencyItem + ":" + strings.Split(text[j], ":")[3])

			pkgName := dependencyItem
			//pkgName := dependencyItem + ":" + strings.Split(text[j], ":")[3]

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
	//log.Println(" Handle pkg: ", text)
	i := 0
	cnt := 0
	subPkgs := make([]string, 5)
	for i < len(text) {
		dependencyItem := strings.Split(text[i], ":")[1]
		//log.Println("			" + subPackage + " is subpackage")
		subpkg := dependencyItem
		//subpkg := dependencyItem + ":" + strings.Split(text[i], ":")[3]

		if !isSubPackage(text[i]) {
			return i
		} else {
			subPkgs[cnt] = subpkg
			tdList[pkgName] = subPkgs
			cnt++
		}
		i++
	}
	return -1
}

func isSubPackage(name string) bool {
	if strings.HasPrefix(name, "\\-") || strings.HasPrefix(name, "   \\-") || strings.HasPrefix(name, "+-") || strings.HasPrefix(name, "|  \\- ") {
		//log.Println("			" + name + " is subpackage")
		//dependencyItem := strings.Split(name, ":")[1]
		//fmt.Println("			" + subPackage + " is subpackage")
		//log.Println("				SubPKG " + dependencyItem + ":" + strings.Split(name, ":")[3])
		return true
	}
	//fmt.Println("	@@@@@ name " + name + " is PKG")
	return false
}

func buildDependenciesGraph(modules []models.Module, tdList map[string][]string) error {
	moduleMap := map[string]models.Module{}
	moduleIndex := map[string]int{}

	//log.Println(" len(modules): ", len(modules))
	for idx, module := range modules {
		moduleMap[module.Name] = module
		moduleIndex[module.Name] = idx
		//fmt.Println("		Module Name: " + module.Name + "  length: " + strconv.Itoa(len(module.Name)) + "  idx: " + strconv.Itoa(idx))
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
				// fmt.Println(" 444444 depModule.Name: ", depModule.Name)
				// fmt.Println(" 55555555 moduleName: " + moduleName + "  length: " + strconv.Itoa(len(moduleName)) + "   depName: " + depName + "  length: " + strconv.Itoa(len(depName)))
				// fmt.Println("  moduleIndex[moduleName]: " + strconv.Itoa(moduleIndex[moduleName]))
				// fmt.Println(" 66666666 len(modules[moduleIndex[moduleName]].Modules): ", len(modules[moduleIndex[moduleName]].Modules))
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
