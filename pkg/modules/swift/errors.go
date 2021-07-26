// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"errors"
)

var errDependenciesNotFound error = errors.New("unable to generate SPDX file, no modules or vendors found. Please install them before running spdx-sbom-generator, e.g.: `swift build`")
