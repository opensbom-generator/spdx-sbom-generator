package spack

import "errors"

type errType error

var errSpackNotFound errType = errors.New("Unable to generate SPDX file, spack is not installed.")
var errDependenciesNotFound errType = errors.New("Unable to generate SPDX file, no spack installs found. Please install them before running spdx-sbom-generator, e.g.: `spack install`")
