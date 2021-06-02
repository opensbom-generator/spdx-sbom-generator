<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
package gomod

import (
	"strings"
)

type command string

var (
	VersionCmd     command = "go version"
	RootModuleCmd  command = "go list -mod readonly -json -m"
	ModulesCmd     command = "go list -mod readonly -json -m all"
	GraphModuleCmd command = "go mod graph"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
