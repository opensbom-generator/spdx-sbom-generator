// SPDX-License-Identifier: Apache-2.0

package nuget

import (
	"strings"
)

type command string

var (
	VersionCmd           command = "dotnet --version"
	LocalPackageCacheCmd command = "dotnet nuget locals global-packages --list"
	RestorePackageCmd    command = "dotnet restore"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))

	// Keep double-quoted strings as a single token
	quoted := false
	tokens := strings.FieldsFunc(cmd, func(r rune) bool {
		if r == '"' {
			quoted = !quoted
		}
		return !quoted && r == ' '
	})
	return tokens
}
