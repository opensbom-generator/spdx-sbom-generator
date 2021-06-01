# SPDX Software Bill of Materials (SBOM) Generator

### NOTE
The CLI is under development. Expect breaking changes until the beta release.

## Overview
A CLI named `spdx-sbom-generator,` that generates SPDX format files. It will understand the ecosystems of most languages, and will connect to the appropriate package management system (OR read it from a local machine) during the run time and get Document creation, Package, Relationships, and Other License information.

CLI will perform the following things:
* Automatically recognize which package management system to connect (OR read it from local machine) based on package manifest file used in the project repository i.e., package.json, pom.xml
* Display ecosystem name i.e npm and project manifest file i.e package.json
* Output format: .spdx .spdx.json, .spdx.rdf (https://spdx.github.io/spdx-spec/1-rationale/#17-format-requirements)
- Ecosystem to support: .NET, Python, Java-Maven, Java-Gradle, Golang, Rust, Node.js, Ruby, PHP, and Elixir

## Available command options
Run help:
```BASH
./spdx-sbom-generator -h

Output Package Manager dependency on SPDX format

Usage:
  spdx-sbom-generator [flags]

Flags:
  -h, --help                   help for spdx-sbom-generator
  -d, --include-depth string   Dependency level (default: all) i.e 0,1,2,3,4 etc (default "all")
  -i, --include-license-text    Include full license text (default: false)
  -o, --output string          <output> Write SPDX to file (default format: 'spdx' - default output "bom.spdx")
  -p, --path string            the path to package file or the path to a directory which will be recursively analyzed for the package files (default '.') (default ".")
  -s, --schema string          <version> Target schema version (default: '2.2') (default "2.2")
  -v, --version string         output the version number
```

### Output options

- `spdx` (Default format)
- `JSON`
- `RDF`

Command output sample option:
```BASH
./spdx-sbom-generator -o bom.spdx
```


#### Output Sample

```
SPDXVersion: SPDX-2.2
DataLicense: CC0-1.0
SPDXID: SPDXRef-DOCUMENT
DocumentName: spdx-sbom-generator
DocumentNamespace: http://spdx.org/spdxpackages/spdx-sbom-generator--57918521-3212-4369-a8ed-3d681ec1d7a1
Creator: Tool: spdx-sbom-generator-XXXXX
Created: 2021-05-23 11:25:29.1672276 -0400 -04 m=+0.538283001

##### Package representing the Go distribution

PackageNam: go
SPDXID: SPDXRef-Package-go
PackageVersion: v0.46.3
PackageSupplier: NOASSERTION
PackageDownloadLocation: pkg:golang/cloud.google.com/go@v0.46.3
FilesAnalyzed: false
PackageChecksum: TEST: SHA-1 224ffa55932c22cef869e85aa33e2ada43f0fb8d
PackageHomePage: pkg:golang/cloud.google.com/go@v0.46.3
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
PackageLicenseComments: NOASSERTION
PackageComment: NOASSERTION

Relationship: SPDXRef-DOCUMENT DESCRIBES SPDXRef-Package-go

##### Package representing the Bigquery Distribution

PackageNam: bigquery
SPDXID: SPDXRef-Package-bigquery
PackageVersion: v1.0.1
PackageSupplier: NOASSERTION
PackageDownloadLocation: pkg:golang/cloud.google.com/go/bigquery@v1.0.1
FilesAnalyzed: false
PackageChecksum: TEST: SHA-1 8168e852b675afc9a63b502feeefac90944a5a2a
PackageHomePage: pkg:golang/cloud.google.com/go/bigquery@v1.0.1
PackageLicenseConcluded: NOASSERTION
PackageLicenseDeclared: NOASSERTION
PackageCopyrightText: NOASSERTION
PackageLicenseComments: NOASSERTION
PackageComment: NOASSERTION

Relationship: SPDXRef-Package-go CONTAINS SPDXRef-Package-bigquery
```

## Data Contract
The interface requires the following functions

```GO
type IPlugin interface {
  SetRootModule(path string) error
  GetVersion() (string, error)
  GetMetadata() PluginMetadata
  GetRootModule(path string) (*Module, error)
  ListUsedModules(path string) ([]Module, error)
  ListModulesWithDeps(path string) ([]Module, error)
  IsValid(path string) bool
  
```

`Module` model definition:

```GO
type Module struct {
  Version          string `json:"Version,omitempty"`
  Name             string
  Path             string `json:"Path,omitempty"`
  LocalPath        string `json:"Dir,noempty"`
  Supplier         SupplierContact
  PackageURL       string
  CheckSum         *CheckSum
  PackageHomePage  string
  LicenseConcluded string
  LicenseDeclared  string
  CommentsLicense  string
  OtherLicense     []*License
  Copyright        string
  PackageComment   string
  Root             bool
  Modules          map[string]*Module
}```

`PluginMetadata` model definition:
```GO
type PluginMetadata struct {
    Name       string
    Slug       string
    Manifest   []string
    ModulePath []string
}
```

### Interface definitions:

* `GetVersion`: returns version of current project platform (development language) version i.e: go version

    **Input**: None

    **Output**: version in string format and error (null in case of successful process)

* `GetMetadata`: returns metadata of identify ecosystem pluging

    **Input**: None

    **Output**: plugin metadata
```GO
PluginMetadata{
    Name:       "Go Modules",
    Slug:       "go-mod",
    Manifest:   []string{"go.mod"},
    ModulePath: []string{"vendor"},
}
```
* `SetRootModule`: sets root package information base on path given

    **Input**: The working directory to read the package from

    **Output**: returns error

* `GetRootModule`: returns root package information base on path given

    **Input**: The working directory to read the package from

    **Output**: returns the Package Information of the root  Module

* `ListUsedModules`: fetches and lists all packages required by the project in the given project directory, this is a plain list of all used modules (no nested or tree view)

    **Input**: The working directory to read the package from

    **Output**: returns the Package Information of the root  Module, and its dependencies in flatten format

* `ListModulesWithDeps`: fetches and lists all packages (root and direct dependencies) required by the project in the given project directory (side-by-side), this is a one level only list of all used modules, and each with its direct dependency only (similar output to `ListUsedModules` but with direct dependency only)

    **Input**: The working directory to read the package from

    **Output**: returns the Package Information of the root  Module, and its direct dependencies

* `IsValid`: check if the project dependency file provided in the contract exists

    **Input**: The working directory to read the package from

    **Output**: True or False

* `HasModulesInstalled`: check whether the current project(based on given path) has the dependent packages installed

    **Input**: The working directory to read the package from

    **Output**: True or False


#### Module Structure JSON Example:
```JSON

{
       "Version": "v0.0.1-2019.2.3",
       "Name": "honnef.co/go/tools",
       "Path": "honnef.co/go/tools",
       "LocalPath": "",
       "Supplier": {
               "Type": "",
               "Name": "",
               "EMail": ""
       },
       "PackageURL": "pkg:golang/honnef.co/go/tools@v0.0.1-2019.2.3",
       "CheckSum": {
               "Algorithm": "SHA-1",
               "Value": "66ed272162df8ef5f9e6d7bece3da6828a4ef3eb"
       },
       "PackageHomePage": "",
       "LicenseConcluded": "",
       "LicenseDeclared": "",
       "CommentsLicense": "",
       "OtherLicense": null,
       "Copyright": "",
       "PackageComment": "",
       "Root": false,
       "Modules": {
               "github.com/BurntSushi/toml": {
                       "Version": "v0.3.1",
                       "Name": "github.com/BurntSushi/toml",
                       "Path": "github.com/BurntSushi/toml",
                       "LocalPath": "",
                       "Supplier": {
                               "Type": "",
                               "Name": "",
                               "EMail": ""
                       },
                       "PackageURL": "pkg:golang/github.com/BurntSushi/toml@v0.3.1",
                       "CheckSum": {
                               "Algorithm": "SHA-1",
                               "Value": "38263d2f264e90324c9e9b3b1933f0e94fde1c7e"
                       },
                       "PackageHomePage": "",
                       "LicenseConcluded": "",
                       "LicenseDeclared": "",
                       "CommentsLicense": "",
                       "OtherLicense": null,
                       "Copyright": "",
                       "PackageComment": "",
                       "Root": false,
                       "Modules": null
               }
        }
}
```

For a more complete JSON example look at [modules.json](./examples/modules.json)

### Utility methods:

* `GetLicenses`: returns the detected license object

    **Input**: The working directory of the package licenses

    **Output**: The package license object
```GO
type License struct {
	ID            string
	Name          string
	ExtractedText string
	Comments      string
	File          string
}
```

* `LicenseSPDXExists`: Check if the package license is a valid SPDX reference

    **Input**: The package license

    **Output**: True or False

### How to register a new Plugin

#### Step 1
Clone project
```BASH
git clone git@github.com:LF-Engineering/spdx-sbom-generator.git
```

#### Step 2
Create a new directory into `./internal/modules/` with package manager name, e.g.: `npm`, you should end with a directory:

```BASH
/internal/modules/npm
```

#### Step 3
Create a Handler file, e.g.:  `handler.go`, and follow Data Contract section above. Define package name, and import section, e.g.:
```GO
package npm

import (
	"path/filepath"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

// rest of the file below
```

#### Step 4
In `handler.go`, define the plugin struct with at least the plugin metadata info, e.g.:
```GO
type npm struct {
	metadata models.PluginMetadata
}
```

#### Step 5
Define plugin registration method (`New` func) with metadata values, e.g:
```GO
// New ...
func New() *npm {
	return &npm{
		metadata: models.PluginMetadata{
			Name:       "Node Package Manager",
			Slug:       "npm",
			Manifest:   []string{"package.json"},
			ModulePath: []string{"node_modules"},
		},
	}
}
```

#### Step 6
In `handler.go`, create the required interface function (Data contract definition above)

```GO
// GetMetadata ...
func (m *npm) GetMetadata() models.PluginMetadata {
  return m.metadata
}

// IsValid ...
func (m *npm) IsValid(path string) bool {
  for i := range m.metadata.Manifest {
    if helper.Exists(filepath.Join(path, m.metadata.Manifest[i])) {
      return true
    }
  }
  return false
}

// HasModulesInstalled ...
func (m *npm) HasModulesInstalled(path string) error {
  for i := range m.metadata.ModulePath {
    if helper.Exists(filepath.Join(path, m.metadata.ModulePath[i])) {
      return nil
    }
  }
  return errDependenciesNotFound
}

// GetVersion ...
func (m *npm) GetVersion() (string, error) {
  output, err := exec.Command("npm", "--version").Output()
  if err != nil {
    return "", err
  }

  return string(output), nil
}

// SetRootModule ...
func (m *npm) SetRootModule(path string) error {
  return nil
}

// GetRootModule ...
func (m *npm) GetRootModule(path string) (*models.Module, error) {
  return nil, nil
}

// ListUsedModules...
func (m *npm) ListUsedModules(path string) ([]models.Module, error) {
  return nil, nil
}

// ListModulesWithDeps ...
func (m *npm) ListModulesWithDeps(path string) ([]models.Module, error) {
  return nil, nil
}
```

#### Step 7
In `modules.go` at `./internal/modules/` directory, register the new plugin. Add the plugin to register to the existing definition

```GO
func init() {
    registeredPlugins = append(registeredPlugins,
            gomod.New(),
            npm.New(),
    )
}
```

## How to work with it
A **Makefile** for the `spdx-sbom-generator` is described below with ability to run, test, lint, and build the project binary for different platforms (Linux, Mac, and Windows)

* Run project on current directory
```BASH
make generate
```
you can provide the CLI parameters that will be passed along the comamnd, e.g.:
```BASH
ARGS="--path /home/ubuntu/projects/expressjs" make generate
```

* Build linux binary
```BASH
make build
```

* Build Mac binary
```BASH
make build-mac
```

* Build Windows binary
```BASH
make build-win
```
