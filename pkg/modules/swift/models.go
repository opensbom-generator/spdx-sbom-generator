// SPDX-License-Identifier: Apache-2.0

package swift

type SwiftPackageDescription struct {
	Name string `json:"name"`
	Path string `json:"path"`

	Dependencies []struct {
		Url         string `json:"url"`
		Requirement struct {
			Revision []string `json:"revision"`
			Range    []struct {
				LowerBound string `json:"lower_bound"`
				UpperBound string `json:"upper_bound"`
			}
		} `json:"requirement"`
	} `json:"dependencies"`

	Platforms []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"platforms"`

	Products []struct {
		Name    string                 `json:"name"`
		Targets []string               `json:"targets"`
		Type    map[string]interface{} `json:"type"`
	} `json:"products"`

	Targets []struct {
		C99Name            string   `json:"c99name"`
		ModuleType         string   `json:"module_type"`
		Name               string   `json:"name"`
		Path               string   `json:"path"`
		ProductMemberships []string `json:"product_memberships"`
		Sources            []string `json:"sources"`
		TargetDependencies []string `json:"target_dependencies"`
		Type               string   `json:"type"`
	} `json:"targets"`

	ToolVersion string `json:"tools_version"`
}

type SwiftPackageDependency struct {
	Name         string                   `json:"name"`
	Url          string                   `json:"url"`
	Version      string                   `json:"version"`
	Path         string                   `json:"path"`
	Dependencies []SwiftPackageDependency `json:"dependencies"`
}
