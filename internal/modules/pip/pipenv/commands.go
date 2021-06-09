// SPDX-License-Identifier: Apache-2.0

package pipenv

import (
	"strings"
)

type command string

// assume pipenv will take care of python version might be python2 or python3
const (
	VersionCmd           command = "pipenv run python -V"
	ModulesCmd           command = "pipenv run pip list -v --format json"
	MetadataCmd          command = "pipenv run pip show {PACKAGE}"
	InstallRootModuleCmd command = "pipenv run pip install -e ."
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
