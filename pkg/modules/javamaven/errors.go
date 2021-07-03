// SPDX-License-Identifier: Apache-2.0

package javamaven

import (
	"errors"
)

type errType error

var errFailedToConvertModules errType = errors.New("failed to convert modules")
var moduleNotFound errType = errors.New("module not found")
