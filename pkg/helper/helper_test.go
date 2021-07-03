// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/spdx/spdx-sbom-generator/pkg/reader"
)

func TestGetCopyright(t *testing.T) {
	licensePath := filepath.Join(getPath(), "..", "modules", "npm", "test", "node_modules", "bcryptjs", "LICENSE")
	r := reader.New(licensePath)
	s := r.StringFromFile()
	res := GetCopyright(s)
	assert.Equal(t, "Copyright (c) 2012 Nevins Bartolomeo <nevins.bartolomeo@gmail.com>", res)

	licensePath2 := filepath.Join(getPath(), "..", "modules", "npm", "test", "node_modules", "shortid", "LICENSE")
	r = reader.New(licensePath2)
	s = r.StringFromFile()
	res = GetCopyright(s)
	assert.Equal(t, "Copyright (c) Dylan Greene", res)
}

func getPath() string {
	cmd := exec.Command("pwd")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(string(output), "\n")

	return path
}
