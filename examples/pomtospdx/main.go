package main

import (
	"encoding/json"
	"fmt"

	_ "github.com/spdx/spdx-sbom-generator/examples/pomtospdx/mvnpom"
	"github.com/spdx/spdx-sbom-generator/pkg/plugin"
)

func main() {
	pg, err := plugin.GetPlugin("mvnpom")
	if err != nil {
		fmt.Println(err)
	}
	spdxdoc, err2 := pg.GetSpdxDocument()
	if err2 != nil {
		fmt.Println(err2)
	}
	spdxdocjson, err3 := json.Marshal(spdxdoc)
	if err3 != nil {
		fmt.Println(err3)
	}
	fmt.Println(string(spdxdocjson))
}
