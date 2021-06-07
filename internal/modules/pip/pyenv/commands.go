// SPDX-License-Identifier: Apache-2.0

package pyenv

import (
	"strings"
)

type command string

// assume each project is using python3 default
const (
	VersionCmd           command = "python3 -V"                                              // generic to check version
	ModulesCmd           command = "bin/python -m pip list --exclude-editable --format json" // venv is local
	MetadataCmd          command = "bin/python -m pip show {PACKAGE}"
	InstallRootModuleCmd command = "bin/python -m pip install -e .."
	RootModuleCmd        command = "bin/python -m pip list -e --format json"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
