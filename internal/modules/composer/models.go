// SPDX-License-Identifier: Apache-2.0

package composer

type ComposerLockFile struct {
	Packages    []ComposerLockPackage
	PackagesDev []ComposerLockPackage `json:"packages-dev"`
}

type ComposerLockPackage struct {
	Name        string
	Version     string
	Type        string
	Dist        ComposerLockPackageDist
	License     []string
	Description string
	Source      ComposerLockPackageSource
	Authors     []ComposerLockPackageAuthor
}
type ComposerLockPackageAuthor struct {
	Name  string
	Email string
}

type ComposerLockPackageSource struct {
	Type      string
	URL       string
	Reference string
}

type ComposerLockPackageDist struct {
	Type      string
	URL       string
	Reference string
	Shasum    string
}

type ComposerProjectInfo struct {
	Name        string
	Description string
	Versions    []string
}

type ComposerTreeList struct {
	Installed []ComposerTreeComponent
}
type ComposerTreeComponent struct {
	Name        string
	Version     string
	Description string
	Requires    []ComposerTreeComponent
}
