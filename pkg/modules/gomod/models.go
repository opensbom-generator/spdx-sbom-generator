// SPDX-License-Identifier: Apache-2.0

package gomod

import (
	"github.com/spdx/spdx-sbom-generator/pkg/helper"
	"github.com/spdx/spdx-sbom-generator/pkg/models"
)

type mod struct {
	metadata   models.PluginMetadata
	rootModule *models.Module
	command    *helper.Cmd
}

type JSONOutput struct {
	Dir        string  `json: "Dir,omitempty"`
	ImportPath string  `json:"ImportPath,omitempty"`
	Name       string  `json:"Name,omitempty"`
	Module     *Module `json:"Module,omitempty"`
}

type Module struct {
	Version   string     `json:"Version,omitempty"`
	Path      string     `json:"Path,omitempty"`
	Dir       string     `json:"Dir,noempty"`
	Replace   modReplace `json:"Replace,omitempty"`
	GoMod     string     `json:"GoMod,omitempty"`
	GoVersion string     `json:"GoVersion,omitempty"`
}

type modReplace struct {
	Path      string `json:"Path,omitempty"`
	Dir       string `json:"Dir,noempty"`
	GoMod     string `json:"GoMod,omitempty"`
	GoVersion string `json:"GoVersion,omitempty"`
}
