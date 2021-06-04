// SPDX-License-Identifier: Apache-2.0

package pipenv

import (
	"strings"
)

type command string

// assume pipenv will take care of python version might be python2 or python3
var (
	VersionCmd command = "pipenv run python -V"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
