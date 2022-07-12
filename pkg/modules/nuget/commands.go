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
	return strings.Fields(cmd)
}
