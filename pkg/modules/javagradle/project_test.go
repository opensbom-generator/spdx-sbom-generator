// SPDX-License-Identifier: Apache-2.0

package javagradle

import (
	fuzztest "git.fuzzbuzz.io/fuzz/testing"
	"testing"
)

const (
	allProperties = `
name: my-artifact
group: com.me
game: basketkball
more-useless-stuff: useless
version: 21.0.0
`
	noVersion = `
name: my-artifact
group: com.me
game: basketkball
more-useless-stuff: useless
`
	noName = `
game: basketkball
group: com.me
more-useless-stuff: useless
version: 21.0.0
`
	noGroup = `
name: my-artifact
game: basketkball
more-useless-stuff: useless
version: 21.0.0
`
)

func TestParseProjectInfo(t *testing.T) {
	pi, err := parseProjectInfo([]byte(allProperties))
	if err != nil {
		t.Fatal(err)
	}
	want := projectInfo{
		name:    "my-artifact",
		version: "21.0.0",
		group:   "com.me",
	}

	if pi != want {
		t.Fatalf("\n got: %q\nwant: %q", pi, want)
	}
}

func TestParseProjectInfo_Failures(t *testing.T) {
	for _, content := range []string{noName, noVersion, noGroup} {
		_, err := parseProjectInfo([]byte(content))
		if err == nil {
			t.Fatal("Want failure, got success")
		}
	}
}

// TestFuzzParseProjectInfo fuzz test for the parseProjectInfo function
func TestFuzzParseProjectInfo(t *testing.T) {
	// Connect to fuzzbuzz
	f := fuzztest.NewChecker(t)
	// run the fuzz test using 100 iterations
	fuzztest.Randomize(f, FuzzParseProject, 100)
}
