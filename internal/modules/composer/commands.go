<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
package composer

import (
	"strings"
)

type command string

var (
	VersionCmd     command = "composer --version"
	ShowModulesCmd command = "composer show -t -f json"
<<<<<<< HEAD
=======
	projectInfoCmd command = "composer show -s -f json"
>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
