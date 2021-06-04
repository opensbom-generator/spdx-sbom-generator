// SPDX-License-Identifier: Apache-2.0

package worker

import "encoding/json"

type Packages struct {
	Name    string `json:"name,omitempty"`
	Version string `json:"version,omitempty"`
}

func LoadModules(data string) []Packages {
	var _modules []Packages
	json.Unmarshal([]byte(data), &_modules)
	return _modules
}
