# SPDX Software Bill of Materials (SBOM) Generator

🚧 THIS PROJECT IS UNDER CONSTRUCTION 🚧

Keep up with work being done on the project by joining the [community call](https://meet.jit.si/SBOM-tools) every Wednesday at 9:30 am Pacific Time.

## Table of Contents
- [Contributing](CONTRIBUTING.md)
- [Overview](#overview)
- [Installation](#installation)
- [Available Command Options](#Available-command-options)
  - [Output Options](#output-options)
    - [Output Sample](#output-sample)
- [Docker Images](#docker-images)
- [Architecture](#architecture)
- [Data Contract](#data-contract)
  - [How To Generate Module Values](#how-to-generate-module-values)
  - [Interface Definitions](#interface-definitions)
    - [Module Structure JSON Example](#module-structure-json-example)
  - [Utility Methods](#utility-methods)
  - [How To Register a New Plugin](#how-to-register-a-new-plugin)
- [How To Work with SPDX SBOM Generator](#how-to-work-with-spdx-sbom-generator) 

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
 * Swift Package Manager (Swift)

To contribute to the project, please refer to the [CONTRIBUTING.md](CONTRIBUTING.md) document.

## Installation 

You can download the following binaries and copy paste the application or binary in your cloned project on your local to generate the SPDX SBOM file. You need to execute  the following in the command line tool:

```
./spdx-sbom-generator
```

The following binaries are available to download for various operating system:

* [MacOS](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.10/spdx-sbom-generator-v0.0.10-darwin-amd64.tar.gz)
* [Linux (x64)](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.10/spdx-sbom-generator-v0.0.10-linux-amd64.tar.gz)
* [Windows (x64)](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.10/spdx-sbom-generator-v0.0.10-windows-amd64.zip)
* [Windows (x86)](https://github.com/spdx/spdx-sbom-generator/releases/download/v0.0.10/spdx-sbom-generator-v0.0.10-windows-386.zip)

If you are using [Homebrew](https://brew.sh/), you can also install [spdx-sbom-generator](https://formulae.brew.sh/formula/spdx-sbom-generator) via `brew install spdx-sbom-generator`.

On Windows, you can also download and install the appropriate binary with [Scoop](https://scoop.sh/): `scoop install spdx-sbom-generator`.

***Note***: The `spdx-sbom-generator` CLI is under development. You may expect some breakages and stability issues with the current release. A stable version is under development and will be available to the open source community in the  upcoming beta release.

## Available Command Options

Use the below command to view different options or flags related to SPDX SBOM generator:

```
./spdx-sbom-generator -h
```

The following different commands are listed when you use the help in the SPDX SBOM generator:

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

The following list supports various formats in which you can generate the SPDX SBOM file:

- `spdx` (Default format)

- `JSON`

- `RDF`  (In progress)



Use the below command to generate the SPDX SBOM file in SPDX format:

```BASH
./spdx-sbom-generator -o /out/spdx/
```

### Output Sample

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

PackageName: go
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

PackageName: bigquery
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

You can run this program using a Docker image that contains `spdx-sbom-generator`.
To do this, first [install Docker](https://docs.docker.com/get-docker/).

You’ll then need to pull (download) a Docker image that contains the program. An easy way is to run `docker pull spdx/spdx-sbom-generator`

[spdx-sbom-generator](https://hub.docker.com/r/spdx/spdx-sbom-generator): this is an Alpine image with the spdx-sbom-generator binary installed. You can re-run the pull command to update the image.

Finally, run the program, using this form

```shell
$ docker run -it --rm \
    -v "/path/to/repository:/repository" \
    -v "$(pwd)/out:/out" \
    spdx/spdx-sbom-generator -p /repository/ -o /out/
```

## Architecture

  ![General Architecture](docs/spdx.png)

## Data Contract

The interface requires the following functions:

```GO
type IPlugin interface {
  SetRootModule(path string) error
  GetVersion() (string, error)
  GetMetadata() PluginMetadata
  GetRootModule(path string) (*Module, error)
  ListUsedModules(path string) ([]Module, error)
  ListModulesWithDeps(path string, globalSettingFile string) ([]Module, error)
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

* `GetVersion`: Returns version of current project platform (development language) version i.e: go version

  **Input**: None

  **Output**: Version in string format and error (null in case of successful process)

* `GetMetadata`: Returns metadata of identify ecosystem pluging

  **Input**: None

  **Output**: Plugin metadata

```GO
PluginMetadata{
    Name:       "Go Modules",
    Slug:       "go-mod",
    Manifest:   []string{"go.mod"},
    ModulePath: []string{"vendor"},
}
```

* `SetRootModule`: Sets root package information base on path given

  **Input**: The working directory to read the package from

  **Output**: Returns error

* `GetRootModule`: Returns root package information base on path given

  **Input**: The working directory to read the package from

  **Output**: Returns the Package Information of the root  Module

* `ListUsedModules`: Fetches and lists all packages required by the project in the given project directory, this is a plain list of all used modules (no nested or tree view)

  **Input**: The working directory to read the package from

  **Output**: Returns the Package Information of the root  Module, and its dependencies in flatten format

* `ListModulesWithDeps`: Fetches and lists all packages (root and direct dependencies) required by the project in the given project directory (side-by-side), this is a one level only list of all used modules, and each with its direct dependency only (similar output to `ListUsedModules` but with direct dependency only)

  **Input**: The working directory to read the package from

  **Output**: Returns the Package Information of the root  Module, and its direct dependencies

* `IsValid`: Check if the project dependency file provided in the contract exists

  **Input**: The working directory to read the package from

  **Output**: True or False

* `HasModulesInstalled`: Check whether the current project(based on given path) has the dependent packages installed

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

* `BuildManifestContent` : Walks through a given directory tree, and generates a content based on file paths

  **Input**: Directory to walk through

  **Output**: Directory tree in bytes

* `GetLicenses`: Returns the detected license object

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
   git clone https://github.com/spdx/spdx-sbom-generator.git
   ```

2. Create a new directory into `./pkg/modules/` with package manager name, for example:  `npm`, you should end with a directory:

   ```
   /pkg/modules/npm

   ```

3. Create a Handler file, for example:  `handler.go`, and follow Data Contract section above. Define package name, and import section as explained in the following code snippet:

   ```
   package npm

   import (
   	"path/filepath"

   	"github.com/spdx/spdx-sbom-generator/pkg/helper"
   	"github.com/spdx/spdx-sbom-generator/pkg/models"
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
   func (m *npm) ListModulesWithDeps(path string, globalSettingFile string) ([]models.Module, error) {
     return nil, nil
   }

   ```



7. In `modules.go` at `./pkg/modules/` directory, register the new plugin. Add the plugin to register to the existing definition.

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

This project’s source code is licensed under the Apache License, Version 2.0. See [LICENSE](https://github.com/spdx/spdx-sbom-generator/tree/main/LICENSES) for the full license text.

## Additional Information

[SPDX](https://spdx.org)

[SPDX SBOM](https://www.linuxfoundation.org/en/blog/spdx-its-already-in-use-for-global-software-bill-of-materials-sbom-and-supply-chain-security/)

[SPDX Tools](https://tools.spdx.org/app/)

[SPDX License List](https://spdx.org/licenses/)

[SPDX GitHub Repos](https://github.com/spdx)
