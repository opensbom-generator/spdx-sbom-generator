# SPDX Software Bill of Materials (SBOM) Generator

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
- `XML`

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
	GetVersion() (string, error)
	GetMetadata() PluginMetadata
	GetModule(path string) ([]Module, error)
	ListModules(path string) ([]Module, error)
	ListAllModules(path string) ([]Module, error)
	IsValid(path string) bool
	HasModulesInstalled(path string) bool
}
```

`Module` model definition:

```GO
type Module struct {
    Version          string
    Name             string
    Path             string
    LocalPath        string
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
}
```

`PluginMetadata` model definition:
```GO
type PluginMetadata struct {
    Name       string
    Slug       string
    Manifest   string
    ModulePath string
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
    Manifest:   "go.mod",
    ModulePath: "vendor",
}
```

* `GetModule`: c$returns root package information base on path given

    **Input**: The working directory to read the package from

    **Output**: retirns the Package Information of the root  Module

* `ListModules`: fetches and lists all packages (root and dependencies) required by the project in the given project directory (side-by-side)

    **Input**: The working directory to read the package from

    **Output**: returns the Package Information of the root  Module, and its dependencies in flatten format

* `ListAllModules`: fetches and lists all packages (root and dependencies) required by the project in the given project directory (nested structure)

    **Input**: The working directory to read the package from

    **Output**: returns the Package Information of the root  Module, and its dependencies in a nested structure

* `IsValid`: check if the project dependency file provided in the contract exists

    **Input**: The working directory to read the package from

    **Output**: True or False

* `HasModulesInstalled`: check whether the current project(based on given path) has the dependent packages installed

    **Input**: The working directory to read the package from

    **Output**: True or False


#### Module Structure JSON Example:
```JSON
{
      "Version": "v1.4.0",
      "Name": "atomic",
      "Path": "go.uber.org/atomic",
      "LocalPath": "",
      "Supplier": {
            "Type": "",
            "Name": "",
            "EMail": ""
            },
      "PackageURL": "pkg:golang/go.uber.org/atomic@v1.4.0",
      "CheckSums": null,
      "PackageHomePage": "pkg:golang/go.uber.org/atomic@v1.4.0",
      "LicenseConcluded": "NOASSERTION",
      "LicenseDeclared": "NOASSERTION",
      "CommentsLicense": "NOASSERTION",
      "OtherLicense": {
            "ID":"",
            "Name":"",
            "ExtractedText":"",
            "Comments":""
            },
      "Copyright": "NOASSERTION",
      "PackageComment": "NOASSERTION",
      "Root": false,
      "Modules": null
}
```

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
			Manifest:   "package.json",
			ModulePath: "node_modules",
		},
	}
}
```

#### Step 5
In `handler.go`, create the required interface function (Data contract definition above)

```GO
// GetMetadata ...
func (m *npm) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *npm) IsValid(path string) bool {
	return helper.FileExists(filepath.Join(path, m.metadata.Manifest))
}

// HasModulesInstalled ...
func (m *npm) HasModulesInstalled(path string) bool {
	return helper.FileExists(filepath.Join(path, m.metadata.ModulePath))
}

// GetVersion ...
func (m *npm) GetVersion() (string, error) {
	return "NPM VERSION", nil
}

// GetModule ...
func (m *npm) GetModule(path string) ([]models.Module, error) {
	return nil, nil
}

// ListModules ...
func (m *npm) ListModules(path string) ([]models.Module, error) {
	return nil, nil
}

// ListAllModules ...
func (m *npm) ListAllModules(path string) ([]models.Module, error) {
	return nil, nil
}
```

#### Step 5
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
