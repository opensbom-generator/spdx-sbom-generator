// SPDX-License-Identifier: Apache-2.0

package pyenv

import (
	"strings"
)

type command string

// assume each project is using python3 default
var (
	VersionCmd  command = "python3 -V"                                              // generic to check version
	ModulesCmd  command = "bin/python -m pip list --exclude-editable --format json" // venv is local
	MetadataCmd command = "bin/python -m pip show {PACKAGE}"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
