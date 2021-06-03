// SPDX-License-Identifier: Apache-2.0

package npm

import (
	"errors"
)

type errType error

var (
	errDependenciesNotFound errType = errors.New("unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `npm install`")
	errNoNpmCommand errType = errors.New("no npm command")
)
