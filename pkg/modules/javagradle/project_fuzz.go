// SPDX-License-Identifier: Apache-2.0

package javagradle

import "git.fuzzbuzz.io/fuzz"

func FuzzParseProject(f *fuzz.F) {
	parseProjectInfo(f.Bytes("Project").Get())
}
