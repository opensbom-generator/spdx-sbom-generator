// SPDX-License-Identifier: Apache-2.0

package javagradle

import (
	"bufio"
	"bytes"
	"fmt"
	"os/exec"
	"strings"
)

type projectInfo struct {
	name    string
	group   string
	version string
}

// returns name, version
func getProjectInfo(path string) (projectInfo, error) {
	cmd := newGradleExec(path).run("properties", "-q")
	out, err := cmd.CombinedOutput()
	if err != nil {
		return projectInfo{}, err
	}
	return parseProjectInfo(out)
}

func parseProjectInfo(out []byte) (projectInfo, error) {
	br := bytes.NewReader(out)
	sc := bufio.NewScanner(br)

	pi := projectInfo{}

	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "version:") {
			split := strings.SplitN(line, ":", 2)
			if len(split) != 2 {
				return pi, fmt.Errorf("Could not parse version: %q", line)
			}
			pi.version = strings.TrimSpace(split[1])

		} else if strings.HasPrefix(line, "name:") {
			split := strings.SplitN(line, ":", 2)
			if len(split) != 2 {
				return pi, fmt.Errorf("Could not parse name: %q", line)
			}
			pi.name = strings.TrimSpace(split[1])
		} else if strings.HasPrefix(line, "group:") {
			split := strings.SplitN(line, ":", 2)
			if len(split) != 2 {
				return pi, fmt.Errorf("Could not parse group: %q", line)
			}
			pi.group = strings.TrimSpace(split[1])
		}
	}
	if pi.version == "" {
		return pi, fmt.Errorf("Could not find version")
	}
	if pi.name == "" {
		return pi, fmt.Errorf("Could not find name")
	}
	if pi.group == "" {
		return pi, fmt.Errorf("Could not find group")
	}
	return pi, nil
}

// origin, hash
// perhaps this can be moved to util
func getGitInfo(path string) (string, string, error) {
	sha, err := exec.Command("git", "describe", `--match=""`, "--always", "--abbrev=40", "--dirty").Output()
	if err != nil {
		return "", "", err
	}
	origin, err := exec.Command("git", "config", "--get", "remote.origin.url").Output()
	if err != nil {
		return "", "", err
	}
	return strings.TrimSpace(string(origin)), strings.TrimSpace(string(sha)), nil
}
