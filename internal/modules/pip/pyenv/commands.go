// SPDX-License-Identifier: Apache-2.0

package pyenv

import (
	"strings"
)

type command string

// Parse ...
func (c command) Parse() []string {
	cmd := strings.TrimSpace(string(c))
	return strings.Fields(cmd)
}
