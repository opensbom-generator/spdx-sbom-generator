// SPDX-License-Identifier: Apache-2.0
package common

import (
	"fmt"
	"strings"

	"github.com/go-git/go-git/v5"
	"github.com/google/uuid"
	"github.com/opensbom-generator/parsers/meta"
	"github.com/spdx/tools-golang/spdx/v2/common"
)

const (
	NoAssertion = "NOASSERTION"
	HttpsPrefix = "https"
)

var (
	replacer *strings.Replacer
)

func init() {
	replacers := []string{"/", ".", "_", "-"}
	replacer = strings.NewReplacer(replacers...)
}

// TODO: complete build package homepage rules
func BuildHomepageURL(url string) string {
	if url == "" {
		return NoAssertion
	}

	if strings.HasPrefix(url, HttpsPrefix) {
		return url
	}

	return fmt.Sprintf("%s://%s", HttpsPrefix, url)
}

func BuildVersion(module meta.Package) string {
	if module.Version != "" {
		return module.Version
	}

	if !module.Root {
		return module.Version
	}

	localGit, err := git.PlainOpen(module.LocalPath)
	if err != nil {
		return ""
	}

	head, err := localGit.Head()
	if err != nil {
		return ""
	}

	return head.Hash().String()[0:7]
}

func SetPkgValue(s string) *common.Supplier {
	if s == "" {
		return nil
	}

	return &common.Supplier{
		Supplier:     s,
		SupplierType: "",
	}
}

func SetPkgSPDXIdentifier(s, v string, root bool) common.ElementID {
	if root {
		return common.ElementID(replacer.Replace(s))
	}

	return common.ElementID(fmt.Sprintf("%s-%s", replacer.Replace(s), v))
}

func BuildNamespace(name, version string) string {
	uuidStr := uuid.New().String()
	if version == "" {
		return fmt.Sprintf("%s://spdx.org/spdxdocs/%s-%s", HttpsPrefix, name, uuidStr)
	}

	return fmt.Sprintf("%s://spdx.org/spdxdocs/%s-%s-%s", HttpsPrefix, name, version, uuidStr)
}

func BuildName(name, version string) string {

	if version == "" {
		return name
	}

	return fmt.Sprintf("%s-%s", name, version)
}
