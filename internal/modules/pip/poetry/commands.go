// SPDX-License-Identifier: Apache-2.0

package poetry

import (
	"strings"
)

type command string

// assume poetry will take care of python version might be python2 or python3
const (
	VersionCmd           command = "poetry run python -V"
	ModulesCmd           command = "poetry run pip list -v --format json"
	MetadataCmd          command = "poetry run pip show {PACKAGE}"
	InstallRootModuleCmd command = "poetry install"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
