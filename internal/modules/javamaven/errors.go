// SPDX-License-Identifier: Apache-2.0

package javamaven

import (
	"errors"
)

type errType error

var errDependenciesNotFound errType = errors.New("Unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `go mod vendor`")
var errBuildlingModuleDependencies errType = errors.New("Error building modules dependencies")
var errFailedToConvertModules errType = errors.New("Failed to convert modules")
