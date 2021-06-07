// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"strings"
)

type command string

var (
	VersionCmd     command = "go version"
	RootModuleCmd  command = "go list -mod readonly -json -m"
	ModulesCmd     command = "go list -deps -json ./..."
	GraphModuleCmd command = "go mod graph"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
