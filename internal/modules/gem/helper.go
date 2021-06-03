package gem

import (
	"bufio"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"runtime"
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
	"strings"
	"sync"
)

var (
	dependencies = []Package{}
	lines        = []Line{}

	Required = map[string]bool{
		"s.name":                          true,
		"spec.name":                       true,
		"s.license":                       true,
		"spec.license":                    true,
		"s.licenses":                      true,
		"spec.licenses":                   true,
		"s.email":                         true,
		"spec.email":                      true,
		"s.homepage":                      true,
		"spec.homepage":                   true,
		"s.authors":                       true,
		"spec.authors":                    true,
		"s.summary":                       true,
		"spec.summary":                    true,
		"s.description":                   true,
		"spec.description":                true,
		"s.add_runtime_dependency":        true,
		"spec.add_runtime_dependency":     true,
		"s.add_development_dependency":    true,
		"spec.add_development_dependency": true,
		"s.add_dependency":                true,
		"spec.add_dependency":             true,
		"s.rubygems_version":              true,
		"spec.rubygems_version":           true,
		"s.required_ruby_version":         true,
		"spec.required_ruby_version":      true,
	}
	spec     = Spec{}
	rootPath *string
)

const (
	TITLE                   = "specs:"
	SPEC_DEPENDENCY_PATH    = "vendor/bundle/ruby"
	SPEC_EXTENSION          = ".gemspec"
	SPEC_DEFAULT_DIR        = "specifications"
	CACHE_DEFAULT_DIR       = "cache"
	GEM_DEFAULT_DIR         = "gems"
	RAKEFILE_DEFAULT_NAME   = "Rakefile"
	LEGACY_LOCK_EXTENSION   = ".lock"
	LICENSE_DEFAULT_FILE    = "LICENSE"
	COPYRIGHT_DEFAULT_LABEL = "Copyright (c)"
	LOCK_EXTENSION          = ".locked"
	GEM_DEFAULT_EXTENSION   = ".gem"
	DETECTION_MODE_SPEC     = "spec"
	DETECTION_MODE_LOCK     = "lock"
	NONE                    = "NO ASSERTION"
)

type (
	Line struct {
		Position  int
		Value     string
		Relations []string
	}
	Package struct {
		Name      string
		Relations []string
	}
	Spec struct {
		Name                    string
		License                 string
		Licenses                []string
		LicenseText             string
		GemLocationDir          string
		CopyRight               string
		Version                 string
		Emails                  []string
		HomePage                string
		Authors                 []string
		Summary                 string
		Description             string
		Checksum                string
		RuntimeDependencies     []string
		DevelopmentDependencies []string
		RubyGemsVersion         string
		RequiredRubyVersion     string
		Specifications          []Spec
	}
)

// Returns the root module
func GetGemRootModule(path string) (*models.Module, error) {

	rootPath = &path
	rootModule := models.Module{}
	rootModule.Modules = make(map[string]*models.Module)
	spec, err := GetSpecDependencies(path)
	if err != nil {
		return nil, err
	}

	licensePkg, err := helper.GetLicenses(spec.GemLocationDir)
	if err == nil {
		rootModule.LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
		rootModule.LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
		if !helper.LicenseSPDXExists(licensePkg.ID) {
			licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
			rootModule.OtherLicense = append(rootModule.OtherLicense, licensePkg)
		}
	}

	rootModule.Name = spec.Name
	rootModule.Version = spec.Version
	rootModule.Copyright = helper.GetCopyright(licensePkg.ExtractedText)
	rootModule.CommentsLicense = licensePkg.Comments
	rootModule.LocalPath = spec.GemLocationDir
	rootModule.Root = true
	rootModule.Path = spec.GemLocationDir
	rootModule.PackageHomePage = spec.HomePage
	rootModule.PackageURL = spec.HomePage
	rootModule.CheckSum = &models.CheckSum{
		Algorithm: models.HashAlgoSHA256,
		Value:     spec.Checksum,
	}

	return &rootModule, nil
}

// Returns the root module,dependencies and associations
func ListGemRootModule(path string) ([]models.Module, error) {

	rootPath = &path
	modules := make([]models.Module, 0)
	childGems := make([]models.Module, 0)
	rootModule, err := GetGemRootModule(path)
	if err != nil {
		return nil, err
	}
	modules = append(modules, *rootModule)
	spec, err := GetSpecDependencies(path)
	if err != nil {
		return nil, err
	}
	for _, dep := range spec.Specifications {

		if dep.Name == rootModule.Name && dep.Version == rootModule.Version {
			continue
		}

		var LicenseDeclared, LicenseConcluded string
		var OtherLicense []*models.License
		licensePkg, err := helper.GetLicenses(dep.GemLocationDir)
		if err == nil {
			LicenseDeclared = helper.BuildLicenseDeclared(licensePkg.ID)
			LicenseConcluded = helper.BuildLicenseConcluded(licensePkg.ID)
			if !helper.LicenseSPDXExists(licensePkg.ID) {
				licensePkg.ID = fmt.Sprintf("LicenseRef-%s", licensePkg.ID)
				OtherLicense = append(rootModule.OtherLicense, licensePkg)
			}
		}

		mod := models.Module{
			Name:             dep.Name,
			Version:          dep.Version,
			Copyright:        helper.GetCopyright(licensePkg.ExtractedText),
			CommentsLicense:  licensePkg.Comments,
			LocalPath:        dep.GemLocationDir,
			LicenseDeclared:  LicenseDeclared,
			LicenseConcluded: LicenseConcluded,
			OtherLicense:     OtherLicense,
			Root:             false,
			Path:             dep.GemLocationDir,
			PackageHomePage:  dep.HomePage,
			PackageURL:       dep.HomePage,
			CheckSum: &models.CheckSum{
				Algorithm: models.HashAlgoSHA256,
				Value:     dep.Checksum,
			},
			Modules: make(map[string]*models.Module),
		}

		for _, child := range dep.RuntimeDependencies {
			var err error
			name, fullname, version := ChildDepInfo(child)

			gemInfo := GemMetaVM{}
			wg := sync.WaitGroup{}
			wg.Add(1)

			go func() {
				gemService, err := NewService(name)
				if err == nil {
					gemInfo, err = gemService.GetGem()
					if err != nil {
						wg.Done()
					}
				}
				gemInfo, err = gemService.GetGem()
				if err != nil {
					wg.Done()
				}
				wg.Done()
			}()
			wg.Wait()

			if err != nil {
				continue
			}

			sub := &models.Module{
				Name:    fullname,
				Version: version,
				Root:    false,
				CheckSum: &models.CheckSum{
					Algorithm: models.HashAlgoSHA256,
					Value:     gemInfo.SHA,
				},
			}

			mod.Modules[name] = sub
			childGems = append(childGems, *sub)

		}

		rootModule.Modules[dep.Name] = &mod
		modules = append(modules, mod)

	}
	modules = append(modules, childGems...)

	return modules, nil
}

// Gets parent and child dependency tree from .gemspec
func GetSpecDependencies(path string) (Spec, error) {
	manifest, err := DetectManifest(path, DETECTION_MODE_SPEC)
	if err != nil {
		return Spec{}, err
	}
	module := GetSpecs(filepath.Join(path, manifest))
	BuildSpecDependencies(filepath.Join(path, SPEC_DEPENDENCY_PATH), false, &module)
	return module, nil
}

// Gets parent and child dependency tree from Gemfile.lock
func GetLockedDependencies(path string) ([]Package, error) {
	manifest, err := DetectManifest(path, DETECTION_MODE_LOCK)
	if err != nil {
		return []Package{}, err
	}
	BuildLockDependencyTree(Content(filepath.Join(path, manifest)))
	if hasNodes(dependencies) {
		return dependencies, nil
	}
	return nil, errors.New("no dependencies were found for project")
}

// Builds parent and child dependency tree from .gemspec
func BuildSpecDependencies(path string, isFullPath bool, module *Spec) {

	files, err := ioutil.ReadDir(path)

	if err != nil {

		log.Fatal(err)
	}

	if !isFullPath {

		for _, f := range files {

			if f.IsDir() {
				fullPath := filepath.Join(path, f.Name(), SPEC_DEFAULT_DIR)
				BuildSpecDependencies(fullPath, true, module)
				break
			}

		}

	}

	cachePath := strings.Replace(path, SPEC_DEFAULT_DIR, CACHE_DEFAULT_DIR, 1)

	name, version, err := RootGem(cachePath, CleanName(module.Name), true)
	versionedName := fmt.Sprintf("%s-%s", name, version)
	if err == nil {
		module.Name = versionedName
		module.Version = GemVersion(versionedName)
	}

	checkSum, err := CheckSum(cachePath, versionedName, true)
	if err == nil && checkSum != "" {
		module.Checksum = checkSum
	}

	copyRight, LicenseText, LicensePath, err := ExtractRootLicense(*rootPath, CleanName(module.Name))
	if err == nil {
		module.CopyRight = copyRight
		module.LicenseText = LicenseText
		module.GemLocationDir = LicensePath
	}

	for i, f := range files {
		if filepath.Ext(f.Name()) == SPEC_EXTENSION {

			specPath := filepath.Join(path, f.Name())

			module.Specifications = append(module.Specifications, GetSpecs(specPath))
			fileName := CleanName(strings.Replace(f.Name(), SPEC_EXTENSION, "", 1))

			checkSum, err := CheckSum(cachePath, fileName, true)
			if err == nil {
				module.Specifications[i].Checksum = checkSum
			}
			module.Specifications[i].Name = fileName

			copyRight, LicenseText, LicensePath, err := ExtractLicense(SPEC_DEPENDENCY_PATH, fileName, false)
			if err == nil {
				module.Specifications[i].CopyRight = copyRight
				module.Specifications[i].LicenseText = LicenseText
				module.Specifications[i].GemLocationDir = LicensePath
				module.Specifications[i].Version = GemVersion(fileName)
			}

		}
	}

}

// launch routines to Get metadata from .gemspec concurrently
func GetSpecs(path string) Spec {
	output := make(chan Spec, 1)
	go MapSpec(Content(path), output)
	return <-output
}

// Speed up the build process concurrently
func MapSpec(rows []string, output chan<- Spec) {
	spec := Spec{}
	for _, row := range rows {
		column := Columns(row)
		if !Required[column] && InvalidRow(row) {
			continue
		}
		ReduceSpec(row, column, &spec)
	}
	output <- spec
}

// Speed up the build process concurrently
func ReduceSpec(row, column string, spec *Spec) {
	switch strings.Trim(column, " ") {
	case "s.name":
		fallthrough
	case "spec.name":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.Name = Unfreeze(value)
	case "s.license":
		fallthrough
	case "spec.license":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.License = value
	case "s.email":
		fallthrough
	case "spec.email":
		_, value := strings.SplitN(strings.TrimLeft(row, "="), " ", 2)[0], strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.Emails = List(value)
	case "s.licenses":
		fallthrough
	case "spec.licenses":
		_, value := strings.SplitN(strings.TrimLeft(row, "="), " ", 2)[0], strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.Licenses = List(value)
	case "s.homepage":
		fallthrough
	case "spec.homepage":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.HomePage = Unfreeze(value)
	case "s.authors":
		fallthrough
	case "spec.authors":
		_, value := strings.SplitN(strings.TrimLeft(row, "="), " ", 2)[0], strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.Authors = List(value)
	case "s.summary":
		fallthrough
	case "spec.summary":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1]
		spec.Summary = Unfreeze(value)
	case "s.description":
		fallthrough
	case "spec.description":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1]
		spec.Description = Unfreeze(value)
	case "s.rubygems_version":
		fallthrough
	case "spec.rubygems_version":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.RubyGemsVersion = Unfreeze(value)
	case "s.required_ruby_version":
		fallthrough
	case "spec.required_ruby_version":
		_, value := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], " ", ""), strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
		spec.RequiredRubyVersion = Unfreeze(value)
	case "s.add_runtime_dependency":
		fallthrough
	case "spec.add_runtime_dependency":
		if strings.ContainsAny(row, "[]") {

			value := fmt.Sprintf("%s%s%s", Clean(row, "<", ">"), " ", Clean(row, "[", "]"))
			fmt.Println("passed")
			spec.RuntimeDependencies = append(spec.RuntimeDependencies, value)
		} else {
			_, value := strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
			spec.RuntimeDependencies = append(spec.RuntimeDependencies, value)
		}
	case "s.add_dependency":
		fallthrough
	case "spec.add_dependency":
		if strings.ContainsAny(row, "[]") {
			value := fmt.Sprintf("%s%s%s", Clean(row, "<", ">"), " ", Clean(row, "[", "]"))
			if !isDuplicate(value, *spec) {
				spec.RuntimeDependencies = append(spec.RuntimeDependencies, value)
			}

		} else {
			_, value := strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
			if !isDuplicate(value, *spec) {
				spec.RuntimeDependencies = append(spec.RuntimeDependencies, value)
			}
		}
	case "s.add_development_dependency":
		fallthrough
	case "spec.add_development_dependency":
		if strings.ContainsAny(row, "[]") {
			value := fmt.Sprintf("%s%s%s", Clean(row, "<", ">"), " ", Clean(row, "[", "]"))
			if !isDuplicate(value, *spec) {
				spec.RuntimeDependencies = append(spec.DevelopmentDependencies, value)
			}
		} else {
			_, value := strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[0], strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), " ", 2)[1], " ", "")
			if !isDuplicate(value, *spec) {
				spec.DevelopmentDependencies = append(spec.DevelopmentDependencies, value)
			}
		}

	}

}

func isDuplicate(value string, spec Spec) bool {
	var skip bool
	if len(spec.RuntimeDependencies) == 0 {
		return skip
	}
	for _, dep := range spec.RuntimeDependencies {
		if dep == value {
			skip = true
			break
		}
	}
	return skip
}

//  Builds Dependency Tree from Gemfile.lock
func BuildLockDependencyTree(rows []string) {

	var startIndex, specPosition int
	var newLines []string

	for i, line := range rows {

		value := strings.Trim(line, " ")

		currentPosition := len(line) - len(strings.TrimLeft(line, " "))

		if value == TITLE {
			startIndex = i
			specPosition = currentPosition
		}

		if startIndex > 0 {
			lines = append(lines, Line{
				Position: currentPosition,
				Value:    value,
			})
			newLines = append(newLines, value)
		}

		if currentPosition < specPosition {

			linesToRead := lines[IndexOf(TITLE, newLines)+1:]

			if hasLines(linesToRead) {
				BuildTree(linesToRead)
				newLines = []string{}
				lines = []Line{}

			} else {
				break
			}
		}

	}

}

// Compute SHA 256 Checksum for gems
func CheckSum(path string, filename string, isFullPath bool) (string, error) {

	var sha string
	files, err := ioutil.ReadDir(path)

	if err != nil {
		log.Fatal(err)
	}

	if !isFullPath {

		for _, f := range files {
			if f.IsDir() {
				fullPath := filepath.Join(path, f.Name(), CACHE_DEFAULT_DIR)
				return CheckSum(fullPath, CleanName(filename), true)
			}
		}

	} else {
		if !strings.Contains(path, CACHE_DEFAULT_DIR) {
			return "", nil
		}
		switch runtime.GOOS {
		case "linux":
			linuxcmd := "sha256sum"
			cmd := exec.Command(linuxcmd, CleanName(filename))
			output, err := cmd.Output()
			if err != nil {
				return "", err
			}
			sha = strings.Fields(string(output))[0]
		case "windows":
			winCmd := `certUtil`
			//@TODO Adjust for windows, try the line commented below.
			//winArgs := fmt.Sprintf(`-hashfile %s SHA256 | findstr /v "hash"`, filename)
			cmd := exec.Command(winCmd, "-hashfile", CleanName(filename), "SHA256", "|", "/v", `"hash"`)
			output, err := cmd.Output()
			if err != nil {
				return "", err
			}
			sha = strings.Fields(string(output))[0]
		case "darwin":
			osxCmd := `shasum`
			cmd := exec.Command(osxCmd, "-a", "256", filepath.Join(path, CleanName(filename)+GEM_DEFAULT_EXTENSION), filepath.Join(path, CleanName(filename)+GEM_DEFAULT_EXTENSION))
			output, err := cmd.Output()
			if err != nil {
				println(err.Error())
				return "", err
			}
			sha = strings.Fields(string(output))[0]

		}

	}

	return sha, nil

}

// Get the root dependency name and version
func RootGem(path string, filename string, isFullPath bool) (string, string, error) {

	var name *string
	var version *string
	if !isFullPath {
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {

			if f.IsDir() {
				fullPath := filepath.Join(path, f.Name(), CACHE_DEFAULT_DIR)
				return RootGem(fullPath, CleanName(filename), true)
			}

		}

	} else {
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}
		for _, f := range files {
			if strings.LastIndex(f.Name(), "-") == -1 {
				continue
			}
			stp := strings.LastIndex(f.Name(), "-")
			runes := []rune(f.Name())
			n := string(runes[0:stp])
			v := strings.Replace(string(runes[stp+1:]), ".gem", "", 1)
			filename = strings.ReplaceAll(filename, `="`, "")
			filename = strings.ReplaceAll(filename, `"`, "")

			name = &n
			if *name == CleanName(filename) {
				version = &v
				break
			}
		}
	}

	if reflect.ValueOf(name).IsNil() || reflect.ValueOf(version).IsNil() {
		return filename, "", errors.New("unable to compute Checksum for " + filename)
	}
	return *name, *version, nil

}

// Extract License Info
func ExtractRootLicense(path string, filename string) (string, string, string, error) {

	var copyright string
	var text string
	var licensePath string

	files, err := ioutil.ReadDir(path)
	if err != nil {
		fmt.Println("error extreacting licence from :" + path)
		log.Fatal(err)
	}
	licensePath = path
	for _, f := range files {
		if strings.Contains(f.Name(), LICENSE_DEFAULT_FILE) {
			path = filepath.Join(path, f.Name())
			break
		}
	}
	data, err := ioutil.ReadFile(path)
	if err != nil {
		fmt.Println("File reading error", err)
		return "", "", "", err
	}
	text = string(data)
	rows := Content(path)
	for _, row := range rows {
		if strings.Contains(row, COPYRIGHT_DEFAULT_LABEL) {
			copyright = row
			break
		}
	}

	return copyright, text, licensePath, nil

}

// Extract License Info
func ExtractLicense(path string, filename string, isFullPath bool) (string, string, string, error) {

	var copyright string
	var text string
	var licensePath string

	if !isFullPath {
		files, err := ioutil.ReadDir(path)
		if err != nil {
			log.Fatal(err)
		}

		for _, f := range files {
			if f.IsDir() {
				fullPath := filepath.Join(path, f.Name())
				return ExtractLicense(fullPath, CleanName(filename), true)
			}
		}

	} else {
		if !strings.Contains(path, GEM_DEFAULT_DIR) {
			path = filepath.Join(path, GEM_DEFAULT_DIR, CleanName(filename))
		}
		files, err := ioutil.ReadDir(path)
		if err != nil {
			fmt.Println("error extreacting licence from :" + path)
			log.Fatal(err)
		}
		licensePath = path
		for _, f := range files {
			if strings.Contains(f.Name(), LICENSE_DEFAULT_FILE) {
				path = filepath.Join(path, f.Name())
				break
			}
		}
		data, err := ioutil.ReadFile(path)
		if err != nil {
			fmt.Println("File reading error", err)
			return "", "", "", err
		}
		text = string(data)
		rows := Content(path)
		for _, row := range rows {
			if strings.Contains(row, COPYRIGHT_DEFAULT_LABEL) {
				copyright = row
				break
			}
		}

	}
	return copyright, text, licensePath, nil

}

// Constructs dependency tree recursively
func BuildTree(linesToRead []Line) {

	var startIndex, stopIndex int
	var children = []Line{}
	var nextBatch = []Line{}

	lastPosition := linesToRead[0].Position

	for i, line := range linesToRead {

		if line.Position > lastPosition {
			if startIndex == 0 {
				startIndex = i
			}
		}
		if line.Position == lastPosition && i > 0 {
			if stopIndex == 0 {
				stopIndex = i
				break
			}
		}
	}

	if stopIndex > 0 {
		children = linesToRead[startIndex:stopIndex]

	} else {
		children = linesToRead[startIndex:]
	}

	parent := linesToRead[0].Value

	dependency := Package{Name: parent}

	for _, line := range children {
		if line.Value == parent {
			continue
		}
		dependency.Relations = append(dependency.Relations, line.Value)
	}

	dependencies = append(dependencies, dependency)

	if stopIndex > 0 {
		nextBatch = linesToRead[stopIndex:]
	}

	if hasLines(nextBatch) {
		BuildTree(nextBatch)
	}

}

// Sanitize names from unknown chars
func CleanName(name string) string {
	s := strings.ReplaceAll(name, "=", "")
	s = strings.ReplaceAll(s, "\"", "")
	s = strings.ReplaceAll(s, "“", "")
	return s
}

// Scans and return file content
func Content(path string) []string {

	file, err := os.Open(path)

	record := []string{}

	if err != nil {
		log.Fatal(err)
	}

	defer file.Close()

	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := scanner.Text()
		record = append(record, line)
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return record

}

// Get the first column of a row
func Columns(row string) string {
	var seperator string = " "
	if strings.Contains(row, "(") {
		seperator = "("
	}
	return strings.SplitN(strings.TrimLeft(row, " "), seperator, 2)[0]
}

// Build a slice from a row 'email,author ...'
func List(row string) []string {
	val := strings.ReplaceAll(strings.SplitN(strings.TrimLeft(row, " "), "=", 2)[1], "[", "")
	val = strings.ReplaceAll(val, "]", "")
	val = Unfreeze(val)
	return strings.Split(val, ",")
}

// Track element positions
func IndexOf(element string, data []string) int {
	for k, v := range data {
		if strings.Trim(v, " ") == element {
			return k
		}
	}
	return -1
}

// Validate data rows
func InvalidRow(row string) bool {
	return !strings.Contains(strings.ReplaceAll(row, " ", ""), "s.add_development_dependency") ||
		!strings.Contains(strings.ReplaceAll(row, " ", ""), "spec.add_development_dependency") &&
			!strings.Contains(strings.ReplaceAll(row, " ", ""), "s.add_dependency") ||
		!strings.Contains(strings.ReplaceAll(row, " ", ""), "spec.add_dependency") ||
		strings.ContainsAny(row, "#{")
}

// Remove unwanted symbols & characters if exists
func Clean(val, from, to string) string {
	a := strings.SplitN(val, from, 2)[1]
	a = strings.SplitN(a, to, 2)[0]
	return a
}

// Remove unwanted word if exists '.freeze is often added by bundler'
func Unfreeze(val string) string {
	return strings.ReplaceAll(val, ".freeze", "")
}

// Check if package slice contains elements
func hasNodes(object []Package) bool {
	return len(object) > 0
}

// Check if line slice contains elements
func hasLines(object []Line) bool {
	return len(object) > 0
}

// Get package version
func GemVersion(name string) string {
	if !strings.Contains(name, "-") {
		return ""
	}
	stp := strings.LastIndex(name, "-")
	runes := []rune(name)
	return string(runes[stp+1:])
}

// Get child dependency info
func ChildDepInfo(value string) (string, string, string) {

	var version, name, fullname string
	stp := strings.Index(value, `"`)
	runes := []rune(value)
	name = string(runes[0:stp])
	rn := strings.Split(string(runes[stp:]), ",")
	for i := 0; i < len(rn); i++ {
		version = version + strings.ReplaceAll(strings.ReplaceAll(rn[i], " ", ""), `"`, "")
	}
	if strings.ContainsAny(version, "#{") {
		version = NONE
	}
	if version != NONE {
		fullname = strings.ReplaceAll(fmt.Sprintf("%s %s", name, version), " ", "")
	}

	return name, fullname, version
}

// Scans the provided path for ecosystem manifest file
func DetectManifest(path, mode string) (string, error) {
	var manifest string
	var err error
	files, err := ioutil.ReadDir(path)
	if err != nil {
		log.Fatal(err)
	}
	for _, f := range files {

		switch mode {
		case DETECTION_MODE_LOCK:
			if filepath.Ext(f.Name()) == LOCK_EXTENSION || filepath.Ext(f.Name()) == LEGACY_LOCK_EXTENSION {
				manifest = f.Name()
				err = errors.New("No file with extension '.lock' was detected in " + path)
			}
		case DETECTION_MODE_SPEC:
			if filepath.Ext(f.Name()) == SPEC_EXTENSION {
				manifest = f.Name()
				err = errors.New("No file with extension '.gemspec' was detected in " + path)
			}
		}

		if manifest != "" {
			break
		}

	}
	if manifest == "" {
		return manifest, err
	}
	return manifest, nil
}

// Auto create Rakefile if not detected
func HasRakefile(path string) bool {

	filename := filepath.Join(path,RAKEFILE_DEFAULT_NAME)
	if _, err := os.Stat(filename); err == nil {
		return true
	} 
	return ioutil.WriteFile(filename, []byte("require \"bundler/gem_tasks\" \ntask :default => :spec"), 0644) == nil
	
}
