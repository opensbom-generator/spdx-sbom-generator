package composer

import (
	"strings"
)

type command string

var (
	VersionCmd     command = "composer --version"
	ShowModulesCmd command = "composer show -t -f json"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
