package javamaven

import (
	"bufio"
	"crypto/sha1"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"strconv"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type command string

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}

// Represent a POM file
type MavenPomProject struct {
	XMLName                xml.Name               `xml:"project"`
	ModelVersion           string                 `xml:"modelVersion"`
	Parent                 Parent                 `xml:"parent"`
	GroupId                string                 `xml:"groupId"`
	ArtifactId             string                 `xml:"artifactId"`
	Version                string                 `xml:"version"`
	Packaging              string                 `xml:"packaging"`
	Name                   string                 `xml:"name"`
	Repositories           []Repository           `xml:"repositories>repository"`
	Properties             Properties             `xml:"properties"`
	DependencyManagement   DependencyManagement   `xml:"dependencyManagement"`
	Dependencies           []Dependency           `xml:"dependencies>dependency"`
	Profiles               []Profile              `xml:"profiles"`
	Build                  Build                  `xml:"build"`
	PluginRepositories     []PluginRepository     `xml:"pluginRepositories>pluginRepository"`
	Modules                []string               `xml:"modules>module"`
	Developers             Developer              `xml:"developers>developer"`
	DistributionManagement DistributionManagement `xml:"distributionManagement"`
}

// Represent the Developer of the project
type Developer struct {
	Name         string `xml:"name"`
	Email        string `xml:"email"`
	Organization string `xml:"organization"`
}

// Represent the DistributionManagement of the project
type DistributionManagement struct {
	DownloadUrl string `xml:"downloadUrl"`
	Status      string `xml:"status"`
}

// Represent the parent of the project
type Parent struct {
	GroupId    string `xml:"groupId"`
	ArtifactId string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// Represent a dependency of the project
type Dependency struct {
	XMLName    xml.Name    `xml:"dependency"`
	GroupId    string      `xml:"groupId"`
	ArtifactId string      `xml:"artifactId"`
	Version    string      `xml:"version"`
	Classifier string      `xml:"classifier"`
	Type       string      `xml:"type"`
	Scope      string      `xml:"scope"`
	Exclusions []Exclusion `xml:"exclusions>exclusion"`
}

// Represent an exclusion
type Exclusion struct {
	XMLName    xml.Name `xml:"exclusion"`
	GroupId    string   `xml:"groupId"`
	ArtifactId string   `xml:"artifactId"`
}

type DependencyManagement struct {
	Dependencies []Dependency `xml:"dependencies>dependency"`
}

// Represent a repository
type Repository struct {
	Id   string `xml:"id"`
	Name string `xml:"name"`
	Url  string `xml:"url"`
}

type Profile struct {
	Id    string `xml:"id"`
	Build Build  `xml:"build"`
}

type Build struct {
	// todo: final name ?
	Plugins []Plugin `xml:"plugins>plugin"`
}

type Plugin struct {
	XMLName    xml.Name `xml:"plugin"`
	GroupId    string   `xml:"groupId"`
	ArtifactId string   `xml:"artifactId"`
	Version    string   `xml:"version"`
	//todo something like: Configuration map[string]string `xml:"configuration"`
	// todo executions
}

// Represent a pluginRepository
type PluginRepository struct {
	Id   string `xml:"id"`
	Name string `xml:"name"`
	Url  string `xml:"url"`
}

// Represent Properties
type Properties map[string]string

func (p *Properties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	*p = map[string]string{}
	for {
		key := ""
		value := ""
		token, err := d.Token()
		if err == io.EOF {
			break
		}
		switch tokenType := token.(type) {
		case xml.StartElement:
			key = tokenType.Name.Local
			err := d.DecodeElement(&value, &start)
			if err != nil {
				return err
			}
			(*p)[key] = value
		}
	}
	return nil
}

type javamaven struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

var errExecutingCmdToGetVersion = errors.New("Error executing command to GetVersion")

// New ...
func New() *javamaven {
	return &javamaven{
		metadata: models.PluginMetadata{
			Name:     "Java Maven",
			Slug:     "Java-Maven",
			Manifest: []string{"pom.xml"},
			// TODO: instead of vendor folder what to mention for java project
			// Currently checking for mvn executable path in PATH variable
			ModulePath: []string{"."},
		},
	}
}

// GetMetadata ...
func (m *javamaven) GetMetadata() models.PluginMetadata {
	fmt.Println("GetMetadata() ")
	return m.metadata
}

// SetRootModule ...
func (m *javamaven) SetRootModule(path string) error {
	fmt.Println(" ********** SetRootModule()  path: ", path)
	module, err := m.getModule(path)
	if err != nil {
		return err
	}

	m.rootModule = &module

	return nil
}

// IsValid ...
func (m *javamaven) IsValid(path string) bool {
	for i := range m.metadata.Manifest {
		if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
			return true
		}
	}
	return false
}

// HasModulesInstalled ...
func (m *javamaven) HasModulesInstalled(path string) error {
	// TODO: How to verify is java project is build
	// Enforcing mvn path to be set in PATH variable
	fname, err := exec.LookPath("mvn")
	if err == nil {
		fname, err = filepath.Abs(fname)
	}
	if err != nil {
		fmt.Println(err)
		return err
	}

	//log.Println(fname)
	return nil
}

// GetVersion ...
func (m *javamaven) GetVersion() (string, error) {
	if err := m.buildCmd("java -version", "."); err != nil {
		return "", err
	}

	return m.command.Output()

	// buf := new(bytes.Buffer)
	// if err := helper.ExecCMD(".", buf, "java", "-version"); err != nil {
	// 	return "", fmt.Errorf("%w : ", errExecutingCmdToGetVersion, err)
	// }
	// defer buf.Reset()

	// return strings.Trim(string(buf.Bytes()), "java version"), nil
}

func (m *javamaven) getModule(path string) (models.Module, error) {
	// if err := m.buildCmd(RootModuleCmd, path); err != nil {
	// 	return models.Module{}, err
	// }

	// buffer := new(bytes.Buffer)
	// if err := m.command.Execute(buffer); err != nil {
	// 	return models.Module{}, err
	// }
	// defer buffer.Reset()

	modules := []models.Module{}
	// if err := NewDecoder(buffer).ConvertJSONReaderToModules(&modules); err != nil {
	// 	return models.Module{}, err
	// }

	// if len(modules) == 0 {
	// 	return models.Module{}, errFailedToConvertModules
	// }

	return modules[0], nil
}

func (m *javamaven) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}

// GetRootModule...
func (m *javamaven) GetRootModule(path string) (*models.Module, error) {
	if m.rootModule == nil {
		module, err := m.getModule(path)
		if err != nil {
			return nil, err
		}

		m.rootModule = &module
	}

	return m.rootModule, nil
}

// GetModule ...
func (m *javamaven) GetModule(path string) ([]models.Module, error) {
	fmt.Println("GetModule() ")
	return nil, nil
}

// ListModules ...
func (m *javamaven) ListModules(path string) ([]models.Module, error) {
	fmt.Println("ListModules() path: ", path)
	dependencyList, err := getDependencyList()
	if err != nil {
		fmt.Println("error in getting mvn dependency list and parsing it")
		return nil, err
	}

	tdList, err1 := getTransitiveDependencyList()
	if err1 != nil {
		fmt.Println("error in getting mvn transitive dependency tree and parsing it")
		return nil, err1
	}
	// Loop over string slice at key.
	fmt.Println("  ******** len(tdList): ", len(tdList))
	for i := range tdList {
		fmt.Println(i, tdList[i])
	}

	pomFile, err2 := os.Open("pom.xml")
	// if we os.Open returns an error then handle it
	if err2 != nil {
		fmt.Println(err2)
		return nil, err2
	}

	//fmt.Println("Successfully Opened pom.xml")
	// defer the closing of our xmlFile so that we can parse it later on
	defer pomFile.Close()

	// // read our opened xmlFile as a byte array.
	pomStr, _ := ioutil.ReadAll(pomFile)
	return parseModules(pomStr, dependencyList)
}

// ListUsedModules...
func (m *javamaven) ListUsedModules(path string) ([]models.Module, error) {
	// fmt.Println(" ********** ListUsedModules()  path: ", path)
	// if err := m.buildCmd(ModulesCmd, path); err != nil {
	// 	return nil, err
	// }

	// buffer := new(bytes.Buffer)
	// if err := m.command.Execute(buffer); err != nil {
	// 	return nil, err
	// }
	// defer buffer.Reset()

	// modules := []models.Module{}
	// if err := NewDecoder(buffer).ConvertJSONReaderToModules(&modules); err != nil {
	// 	return nil, err
	// }

	var modules []models.Module
	return modules, nil
}

// ListAllModules ...
func (m *javamaven) ListAllModules(path string) ([]models.Module, error) {
	fmt.Println("ListAllModules() ")
	models, err := m.ListModules(path)
	if err != nil {
		fmt.Println(err)
		return nil, err
	}

	return models, nil
}

func (m *javamaven) ListModulesWithDeps(path string) ([]models.Module, error) {

	var modules []models.Module
	return modules, nil
}

// Update package supplier information
func updatePackageSuppier(mod models.Module, developer Developer) {
	fmt.Println(" ****** developer.Name: "+developer.Name+" developer.Email: "+developer.Email+"  developer.Organization: ", developer.Organization)
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
	fmt.Println(" ****** distManagement.DownloadUrl: ", distManagement.DownloadUrl)
	if len(distManagement.DownloadUrl) > 0 && (strings.HasPrefix(distManagement.DownloadUrl, "http") ||
		strings.HasPrefix(distManagement.DownloadUrl, "https")) {
		mod.PackageHomePage = distManagement.DownloadUrl
	}
}

// parseModules parses the output of `go list -json -m` into a Module slice
func parseModules(reader []byte, dependencyList []string) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	//jsonDecoder := json.NewDecoder(reader)

	// Load project from string
	var project MavenPomProject
	//var project mvnpomparser.MavenProject
	if err := xml.Unmarshal([]byte(reader), &project); err != nil {
		log.Fatalf("unable to unmarshal pom file. Reason: %s", err)
	}

	var mod models.Module
	if len(project.Name) == 0 {
		mod.Name = project.ArtifactId
	} else {
		mod.Name = project.Name
	}
	updatePackageSuppier(mod, project.Developers)
	updatePackageDownloadLocation(mod, project.DistributionManagement)
	mod.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA1,
		Value:     readCheckSum(mod.Path),
	}
	modules = append(modules, mod)

	// iterate over Modules
	for _, module := range project.Modules {
		var mod models.Module
		mod.Name = module
		//mod.Version = modules.Version
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(module),
		}
		modules = append(modules, mod)
	}

	// iterate over dependencies
	for _, dep := range project.Dependencies {
		var mod models.Module
		mod.Name = path.Base(dep.ArtifactId)
		mod.Version = dep.Version
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
				fmt.Println("dependency " + dependencyItem + ":" + strings.Split(dependencyList[i], ":")[3] + " already exists")
				found = true
				break
			}
		}

		if !found {
			var mod models.Module
			mod.Name = path.Base(dependencyItem)
			mod.Version = strings.Split(dependencyList[i], ":")[3]
			fmt.Println("	**** Adding dependency: " + strings.Split(dependencyList[i], ":")[1] + ":" + strings.Split(dependencyList[i], ":")[3])
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
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(plugin.ArtifactId),
		}
		modules = append(modules, mod)
	}

	return modules, nil
}

// this is just a test
func readCheckSum(content string) string {
	//	fmt.Println("readCheckSum() ")
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// capture replaces os.Stdout with a writer that buffers any data written
// to os.Stdout. Call the returned function to cleanup and get the data
// as a string.
func stdOutCapture() func() (string, error) {
	r, w, err := os.Pipe()
	if err != nil {
		panic(err)
	}

	done := make(chan error, 1)

	save := os.Stdout
	os.Stdout = w

	var buf strings.Builder

	go func() {
		_, err := io.Copy(&buf, r)
		r.Close()
		done <- err
	}()

	return func() (string, error) {
		os.Stdout = save
		w.Close()
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

	fmt.Println("***** capturedOutput: \n", capturedOutput)
	s := strings.Split(capturedOutput, "\n")
	return s, err
}

func getTransitiveDependencyList() (map[string][]string, error) {
	fmt.Println("111111")
	command := exec.Command("mvn", "dependency:tree", "-DappendOutput=true", "-DoutputFile=/tmp/TodayOutput.txt")
	fmt.Println("22222")
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
			fmt.Println("line number "+strconv.Itoa(j)+" PKG Name:", text[j])
			dependencyItem := strings.Split(text[j], ":")[1]
			fmt.Println("				PKG " + dependencyItem + ":" + strings.Split(text[j], ":")[3])

			pkgName := dependencyItem + ":" + strings.Split(text[j], ":")[3]

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
	//fmt.Println(" Handle pkg: ", text)
	i := 0
	cnt := 0
	subPkgs := make([]string, 5)
	for i < len(text) {
		dependencyItem := strings.Split(text[i], ":")[1]
		//fmt.Println("			" + subPackage + " is subpackage")
		subpkg := dependencyItem + ":" + strings.Split(text[i], ":")[3]

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
		fmt.Println("			" + name + " is subpackage")
		dependencyItem := strings.Split(name, ":")[1]
		//fmt.Println("			" + subPackage + " is subpackage")
		fmt.Println("				SubPKG " + dependencyItem + ":" + strings.Split(name, ":")[3])
		return true
	}
	//fmt.Println("	@@@@@ name " + name + " is PKG")
	return false
}

