# SPDX Software Bill of Materials (SBOM) Generator

## Overview

[Software Package Data Exchange](https://spdx.org/tools) (SPDX) is an open standard for communicating software bill of materials (SBOM) information that supports accurate identification of software components, explicit mapping of relationships between components, and the association of security and licensing information with each component.

`spdx-sbom-generator`tool to help those in the community that want to generate SPDX Software Bill of Materials (SBOMs) with current package managers.   It has a command line Interface (CLI) that lets you generate SBOM information, including components, licenses, copyrights, and security references of your software using SPDX v2.2 specification and aligning with the current known minimum elements from NTIA. It automatically determines which package managers or build systems are actually being used by the software.  

`spdx-sbom-generator`is supporting the following package managers:
 
 * GoMod (go)
 * Cargo (Rust)
 * Composer (PHP)
 * DotNet (.NET)
 * Maven (Java)
 * NPM (Node.js)
 * Yarn (Node.js)
 * PIP (Python)
 * Pipenv (Python)
 * Gems (Ruby) 

## Installation:

* [macOS](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.7/spdx-sbom-generator-v0.0.7-darwin-amd64.tar.gz)
* [Linux (x64)](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.7/spdx-sbom-generator-v0.0.7-linux-amd64.tar.gz)
* [Windows (x64)](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.7/spdx-sbom-generator-v0.0.7-windows-amd64.zip)
* [Windows (x86)](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.7/spdx-sbom-generator-v0.0.7-windows-386.zip)

***Note***: The `spdx-sbom-generator` CLI is under development. You may expect some breakages and stability issues with the current release. A stable version is under development and will be available to the open source community in the  upcoming beta release.

## Available command Options
Run help:
```BASH
./spdx-sbom-generator -h

Output Package Manager dependency on SPDX format

Usage:
  spdx-sbom-generator [flags]

Flags:
  -h, --help                   help for spdx-sbom-generator
  -i, --include-license-text   include full license text (default: false)
  -o, --output-dir string      directory to write output file to (default: current directory)
  -p, --path string            the path to package file or the path to a directory which will be recursively analyzed for the package files (default '.') (default ".")
  -s, --schema string          <version> Target schema version (default: '2.2') (default "2.2")
  -f, --format string          output file format (default: 'spdx')
  -g, --global-settings string    Alternate path for the global settings file for Java Maven
```

### Output Options

- `spdx` (Default format)

- `JSON` (In progress)

- `RDF`  (In progress)



Command output sample option:
```BASH
./spdx-sbom-generator -o /out/spdx/
```

#### Output Sample

The following snippet is a sample SPDX SBOM file:

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

## Docker Images

Currently few Docker images are supported:

[spdx/spdx-sbom-generator](https://hub.docker.com/r/spdx/spdx-sbom-generator) - Alpine image and spdx-sbom-generator binary installed

```shell
$ docker run -it --rm \
    -v "/path/to/repository:/repository" \
    -v "$(pwd)/out:/out" \
    spdx/spdx-sbom-generator -p /repository -o /out/spdx/
```

## Data Contract
The interface requires the following functions:

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
}
```

`PluginMetadata` model definition:

```GO
type PluginMetadata struct {
    Name       string
    Slug       string
    Manifest   []string
    ModulePath []string
}
```

### How to Generate Module Values

* `CheckSum`: We have built an internal method that calculates CheckSum for a given content (in bytes) using algorithm that is defined on `models.CheckSum`.
You now have an option to provide `Content` field for `models.CheckSum{}` and CheckSum will calculate automatically, but if you want to calculate CheckSum  on your own
you still can provide `Value` field for `models.CheckSum{}`.

Also, you can generate a manifest from a given directory tree using utility/helper method `BuildManifestContent`, and that is what is used for gomod plugin as `Content` value.

### Interface Definitions

The following list provides the interface definitions:

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

#### Module Structure JSON Example

The sample module structure JSON Code snippet is provided in the following code snippet:

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

For a more complete JSON example look at [modules.json](./examples/modules.json).

### Utility Methods

The following list provide the utility methods:

* `BuildManifestContent` walks through a given directory tree, and generates a content based on file paths

    **Input**: Directory to walk through

    **Output**: directory tree in bytes

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

### How to Register a New Plugin

To register for a new plugin, perform the following steps:

1. Clone a project.

   ```
   git clone git@github.com:LF-Engineering/spdx-sbom-generator.git
   ```

2. Create a new directory into `./internal/modules/` with package manager name, for example:  `npm`, you should end with a directory:

   ```
   /internal/modules/npm

   ```

3. Create a Handler file, for example:  `handler.go`, and follow Data Contract section above. Define package name, and import section as explained in the following code snippet:

   ```
   package npm

   import (
   	"path/filepath"

   	"spdx-sbom-generator/internal/helper"
   	"spdx-sbom-generator/internal/models"
   )

   // rest of the file below

   ```



4. In `handler.go`, define the plugin struct with at least the plugin metadata info as explained in the following code snippet:

   ```
   type npm struct {
   	metadata models.PluginMetadata
   }

   ```



5. Define plugin registration method (`New` func) with metadata values as explained in the following code snippet:

   ```
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



6. In `handler.go`, create the required interface function (Data contract definition above).

   ```
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



7. In `modules.go` at `./internal/modules/` directory, register the new plugin. Add the plugin to register to the existing definition.

   ```
   func init() {
       registeredPlugins = append(registeredPlugins,
               gomod.New(),
               npm.New(),
       )
   }

   ```



## How to Work With SPDX SBOM Generator
A **Makefile** for the `spdx-sbom-generator` is described below with ability to run, test, lint, and build the project binary for different platforms (Linux, Mac, and Windows).

Perform the following steps to work with SPDX SBOM Generator:

1. Run project on current directory.

   ```
   make generate
   ```

   you can provide the CLI parameters that will be passed along the command, for example:

   ```
   ARGS="--path /home/ubuntu/projects/expressjs" make generate
   ```

2. Build Linux Intel/AMD 64-bit binary.

   ```
   make build
   ```

3. Build Mac Intel/AMD 64-bit binary.

   ```
   make build-mac
   ```

4. Build Mac ARM 64-bit binary.

   ```
   make build-mac-arm64
   ```

5. Build Windows Intel/AMD 64-bit binary.

   ```
   make build-win
   ```



Licensing
---------
docker/cli is licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/spdx/spdx-sbom-generator/blob/master/LICENSE) for the full license text.

## Additional Information

[SPDX](https://spdx.org)

[SPDX SBOM](https://www.linuxfoundation.org/en/blog/spdx-its-already-in-use-for-global-software-bill-of-materials-sbom-and-supply-chain-security/)

[SPDX Tools](https://tools.spdx.org/app/)

[SPDX License List](https://spdx.org/licenses/)

[SPDX GitHub Repos](https://github.com/spdx)
