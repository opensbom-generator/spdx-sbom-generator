// SPDX-License-Identifier: Apache-2.0

package worker

import "encoding/json"

type PackageList []Packages

type Packages struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

func LoadModules(data string) PackageList {
	var _modules PackageList
	json.Unmarshal([]byte(data), &_modules)
	return _modules
}
