// SPDX-License-Identifier: Apache-2.0

package cargo

import (
	"bytes"
	"strings"

	"github.com/spdx/spdx-sbom-generator/pkg/helper"
)

type command string

var (
	VersionCmd        command = "cargo --version"
	ModulesCmd        command = "cargo metadata --format-version=1"
	RootModuleNameCmd command = "cargo pkgid"
	CargoTomlFile     string  = "Cargo.toml"
	CargoLockFile     string  = "Cargo.lock"
)

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}

func (m *mod) buildCmd(cmd command, path string) error {
	cmdArgs := cmd.Parse()
	if cmdArgs[0] != "cargo" {
		return errNoCargoCommand
	}

	command := helper.NewCmd(helper.CmdOptions{
		Name:      cmdArgs[0],
		Args:      cmdArgs[1:],
		Directory: path,
	})

	m.command = command

	return command.Build()
}

func (m *mod) runTask(task command, path string) (*bytes.Buffer, error) {

	err := m.buildCmd(task, path)
	if err != nil {
		return nil, err
	}

	buffer := new(bytes.Buffer)
	if err := m.command.Execute(buffer); err != nil {
		return nil, err
	}

	return buffer, nil
}
