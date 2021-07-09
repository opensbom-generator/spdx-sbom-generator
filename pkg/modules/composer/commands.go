// SPDX-License-Identifier: Apache-2.0

package composer

import (
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
)

type command string

var (
	VersionCmd              command = "composer --version"
	ShowModulesCmd          command = "composer show -t -f json"
	projectInfoCmd          command = "composer show -s -f json"
	COMPOSER_LOCK_FILE_NAME string  = "composer.lock"
	COMPOSER_JSON_FILE_NAME string  = "composer.json"
	PACKAGE_JSON            string  = "package.json"
	COMPOSER_VENDOR_FOLDER  string  = "vendor"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}

func (m *composer) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if cmdArgs[0] != "composer" {
		return errNoComposerCommand
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}
