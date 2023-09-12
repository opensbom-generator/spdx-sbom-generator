// SPDX-License-Identifier: Apache-2.0

package spack

var (
	spackRepo   = "https://github.com/spack/spack"
	spackBranch = "develop"
)

type SpackPackage struct {
	Spec struct {
		Meta struct {
			Version int `json:"version"`
		} `json:"_meta"`
		Nodes []Node `json:"nodes"`
	} `json:"spec"`
}

type Node struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Arch    struct {
		Platform   string `json:"platform"`
		PlatformOs string `json:"platform_os"`
		Target     struct {
			Name       string   `json:"name"`
			Vendor     string   `json:"vendor"`
			Features   []string `json:"features"`
			Generation int      `json:"generation"`
			Parents    []string `json:"parents"`
		} `json:"target"`
	} `json:"arch"`
	Compiler struct {
		Name    string `json:"name"`
		Version string `json:"version"`
	} `json:"compiler"`
	Namespace    string                 `json:"namespace"`
	Parameters   map[string]interface{} `json:"parameters,omitempty"`
	PackageHash  string                 `json:"package_hash"`
	Dependencies []struct {
		Name string   `json:"name"`
		Hash string   `json:"hash"`
		Type []string `json:"type"`
	} `json:"dependencies,omitempty"`
	Hash string `json:"hash"`
}
