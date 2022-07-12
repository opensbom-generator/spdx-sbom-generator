// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"errors"
)

type errType error

var errNoComposerCmd errType = errors.New("No composer command")
var errDependenciesNotFound errType = errors.New("Unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `go mod vendor`")
var errBuildlingModuleDependencies errType = errors.New("Error building modules dependencies")
var errNoGoCommand errType = errors.New("No Golang command")
var errFailedToConvertModules errType = errors.New("Failed to convert modules")
var errNoMainModule errType = errors.New("No main module found")
