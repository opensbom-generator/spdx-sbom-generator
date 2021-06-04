// SPDX-License-Identifier: Apache-2.0

package worker

import (
	"io"
	"log"
	"os"
	"path/filepath"
	"spdx-sbom-generator/internal/helper"
	"strings"
)

const ModuleDotVenv = ".venv"
const ModuleVenv = "venv"
const PyvenvCfg = "pyvenv.cfg"
const VirtualEnv = "VIRTUAL_ENV"

func IsRequirementMeet(root bool, data string) bool {
	_modules := LoadModules(data)
	if root && len(_modules) == 1 {
		return true
	} else if !root && len(_modules) > 3 {
		return true
	}
	return false
}

func GetVenFromEnvs() (bool, string, string) {
	venvfullpath := os.Getenv(VirtualEnv)
	splitstr := strings.Split(venvfullpath, "/")
	venv := splitstr[len(splitstr)-1]
	if len(venvfullpath) > 0 {
		return true, venv, venvfullpath
	}
	return false, venv, venvfullpath
}

func HasDefaultVenv(path string) (bool, string, string) {
	modules := []string{ModuleDotVenv, ModuleVenv}
	for i := range modules {
		venvfullpath := filepath.Join(path, modules[i])
		if helper.Exists(filepath.Join(path, modules[i])) {
			return true, modules[i], venvfullpath
		}
	}
	return false, "", ""
}

func HasPyvenvCfg(path string) bool {
	return helper.Exists(filepath.Join(path, PyvenvCfg))
}

func ScanPyvenvCfg(files *string, folderpath *string) filepath.WalkFunc {
	return func(path string, info os.FileInfo, err error) error {
		if err != nil {
			log.Fatal(err)
		}
		if info.IsDir() {
			if HasPyvenvCfg(path) {
				*files = info.Name()
				p, _ := filepath.Abs(path)
				*folderpath = p

				// This is to break the walk for first enviironment found.
				// The assumption is there will be only one environment present
				return io.EOF
			}
		}
		return nil
	}
}

func SearchVenv(path string) (bool, string, string) {
	var venv string
	var venvfullpath string
	var state bool

	// if virtual env is active
	state, venv, venvfullpath = GetVenFromEnvs()
	if state {
		return true, venv, venvfullpath
	}

	state, venv, venvfullpath = HasDefaultVenv(path)
	if state {
		return state, venv, venvfullpath
	}

	err := filepath.Walk(path, ScanPyvenvCfg(&venv, &venvfullpath))
	if err == io.EOF {
		err = nil
	}

	if err == nil {
		return true, venv, venvfullpath
	}

	return false, venv, venvfullpath
}
