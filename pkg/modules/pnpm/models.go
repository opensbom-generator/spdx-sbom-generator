// SPDX-License-Identifier: Apache-2.0

package pnpm

type dependency struct {
	Name         string
	PkPath       string
	Version      string
	Resolved     string
	Integrity    string
	Dependencies []string
	Belonging    string
}
