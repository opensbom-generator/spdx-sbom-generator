package helper

import (
	"io"
	"os"
	"os/exec"
	"spdx-sbom-generator/internal/reader"
	"strings"
)

// FileExists ...
func FileExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}

// StringSliceIndex determines the index of a given string in a given string slice.
func StringSliceIndex(haystack []string, needle string) int {
	for i := range haystack {
		if haystack[i] == needle {
			return i
		}
	}
	return -1
}

func ExecCMD(modulePath string, writer io.Writer, cmdParameter ...string) error {
	cmd := exec.Command(cmdParameter[0], cmdParameter[1:]...)
	cmd.Dir = modulePath
	cmd.Stdout = writer
	return cmd.Run()
}

// GetCopyrightText ...
func GetCopyrightText(path string) string {
	r := reader.New(path)
	c := r.StringFromFile()
	ind := strings.Index(c, "Copyright (c)")
	if ind < 0 {
		return ""
	}
	copyWrite := strings.Split(c[ind:], `\n`)
	return copyWrite[0]
}
