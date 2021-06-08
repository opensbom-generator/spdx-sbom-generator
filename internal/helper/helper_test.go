// SPDX-License-Identifier: Apache-2.0

package helper

import (
	"fmt"
	"github.com/stretchr/testify/assert"
	"os/exec"
	"path/filepath"
	"spdx-sbom-generator/internal/reader"
	"strings"
	"testing"
)

func TestGetCopyright(t *testing.T) {
	path := fmt.Sprintf("%s/test", getPath())
	licensePath := filepath.Join(path, "node_modules", "bcryptjs", "LICENSE")
	if Exists(licensePath) {
		r := reader.New(licensePath)
		s := r.StringFromFile()
		res := GetCopyright(s)
		assert.Equal(t, "Copyright (c) 2012 Nevins Bartolomeo <nevins.bartolomeo@gmail.com>", res)
	}

	licensePath2 := filepath.Join(path, "node_modules", "shortid", "LICENSE")
	if Exists(licensePath2) {
		r := reader.New(licensePath2)
		s := r.StringFromFile()
		res := GetCopyright(s)
		assert.Equal(t, "Copyright (c) Dylan Greene", res)
	}
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
