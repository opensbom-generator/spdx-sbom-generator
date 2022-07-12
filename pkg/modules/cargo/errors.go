// SPDX-License-Identifier: Apache-2.0

package cargo

import (
	"errors"
)

type errType error

var errNoCmd errType = errors.New("No cargo command")
var errDependenciesNotFound errType = errors.New("Unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `cargo build`")
var errBuildlingModuleDependencies errType = errors.New("Error building modules dependencies")
var errNoCargoCommand errType = errors.New("No Cargo command")
var erroRootPackageInformation errType = errors.New("Failed to read root folder information. Please verify you can run `cargo pkgid`")
var errFailedToConvertModules errType = errors.New("Failed to convert modules")
