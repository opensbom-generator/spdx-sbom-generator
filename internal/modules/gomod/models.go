// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type mod struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

type MOD struct {
	Version   string `json:"Version,omitempty"`
	Path      string `json:"Path,omitempty"`
	Dir       string `json:"Dir,noempty"`
	Replace   modReplace
	GoMod     string
	GoVersion string
}

type modReplace struct {
	Path      string
	Dir       string
	GoMod     string
	GoVersion string
}
