package helper

import (
	"io"
	"os"
	"os/exec"
)

// FileExists ...
func FileExists(path string) bool {
	_, err := os.Stat(path)
	if err != nil {
		return false
	}

	isValid := !os.IsNotExist(err)

	return isValid
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
