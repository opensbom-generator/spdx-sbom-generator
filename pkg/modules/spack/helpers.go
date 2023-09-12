package spack

import (
	"os"
	"path/filepath"
	"regexp"
)

// getInstallPaths returns all nested .spack metadata folders indicating package installs
func (m *spack) getInstallPaths(root string) []string {
	regex, _ := regexp.Compile(`spec.json$`)
	installs := []string{}
	seen := make(map[string]bool)
	filepath.Walk(root, func(path string, info os.FileInfo, err error) error {
		if err == nil && regex.MatchString(info.Name()) {
			if _, ok := seen[path]; !ok {
				installs = append(installs, path)

			}
		}
		return nil
	})
	// Generally if we have an error, just don't return installs
	return installs
}

// installDir returns the spack install directory of packages
func (m *spack) installDir() string {
	return filepath.Join(m.spackRoot, m.metadata.ModulePath[0], "spack")
}

// getInstallPath give the root of a package install from a specfile
func getInstallPath(specfile string) string {
	return filepath.Dir(filepath.Dir(specfile))
}

func (m *spack) getLocalPath(fullpath string) string {
	localPath, err := filepath.Rel(m.spackRoot, fullpath)
	if err != nil {
		localPath = fullpath
	}
	return localPath
}
