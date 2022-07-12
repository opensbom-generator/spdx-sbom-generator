// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"errors"
	"io"
	"os/exec"
)

var errEmptyArgs = errors.New("At least one argument is required")

// CmdOptions ...
type CmdOptions struct {
	Name      string
	Args      []string
	Directory string
}

// Cmd ...
type Cmd struct {
	options CmdOptions
	cmd     *exec.Cmd
}

// NewCmd ...
func NewCmd(opts CmdOptions) *Cmd {
	return &Cmd{
		options: opts,
	}
}

// Build ...
func (c *Cmd) Build() error {
	if len(c.options.Args) == 0 {
		return errEmptyArgs
	}

	c.cmd = exec.Command(c.options.Name, c.options.Args...)
	c.cmd.Dir = c.options.Directory

	return nil
}

// Execute ...
func (c *Cmd) Execute(w io.Writer) error {
	c.cmd.Stdout = w
	return c.cmd.Run()
}

// Execute ...
func (c *Cmd) Output() (string, error) {
	output, err := c.cmd.Output()
	if err != nil {
		return "", err
	}
	return string(output), err
}
