// SPDX-License-Identifier: Apache-2.0

package javagradle

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

type depInfo struct {
	root  []string
	all   []string
	graph map[string][]string
}

// collect all non-transitive dependencies from all configuration (compile, test, runtime, etc)
// perhaps this should be limited to just runtimeClasspath, but there's no real way to know
// what the final packager is going to package into the bom, what a dilemma
func getDependencies(dir string) (depInfo, error) {
	return dependencies(dir, ":dependencies")
}

// collect all non-transitive dependencies from the build classpath, this is basically the dependencies
// used to build the project. It's not clear to me that it's necessary to include these, but gradle plugins
// can end up doing whatever they want to the final artifact. If we're trying to generate an sbom
// *before* build.
// Leave them out for now, but include them if we think we need to.
func getBuildDependencies(dir string) (depInfo, error) {
	return dependencies(dir, ":buildEnvironment")
}

func dependencies(dir string, command string) (depInfo, error) {
	out, err := newGradleExec(dir).run(command, "-q").CombinedOutput()
	if err != nil {
		log.Println(string(out))
		return depInfo{}, err
	}
	return parseDependencyOutput(out)
}

// root dependencies, transitive dependency graph
func parseDependencyOutput(out []byte) (depInfo, error) {
	br := bytes.NewReader(out)
	sc := bufio.NewScanner(br)

	// the only valid dependency patterns
	dp := regexp.MustCompile(`^(([|]|[ ])[ ]{4})*([+]|[\\])---`)

	rootDeps := map[string]bool{}
	// map of deps and their children
	deps := make(map[string][]string)

	// the last spotted dependency
	var last string
	// the current parent
	var parents []string

	for sc.Scan() {
		line := sc.Text()
		if dp.MatchString(line) {
			split := strings.SplitN(line, "--- ", 2)
			if len(split) != 2 {
				return depInfo{}, fmt.Errorf("Parse error %v on : %q", len(split), line)
			}
			current := split[1]

			depth := (strings.Index(line, "---") - 1) / 4
			if len(parents) > depth {
				parents = parents[:depth]
			} else if len(parents) < depth {
				parents = append(parents, last)
			}
			parents = parents[:depth]
			if len(parents) > 0 {
				cp := parents[len(parents)-1]
				deps[cp] = append(deps[cp], current)
			} else {
				rootDeps[current] = true
			}

			// add current to map
			if _, ok := deps[current]; !ok {
				deps[current] = []string{}
			}
			last = current
		}
	}
	rootDepsList := make([]string, len(rootDeps))
	i := 0
	for k := range rootDeps {
		rootDepsList[i] = k
		i++
	}

	allDeps := make([]string, len(deps))
	i = 0
	for k := range deps {
		allDeps[i] = k
		i++
	}

	ret := depInfo{
		root:  rootDepsList,
		all:   allDeps,
		graph: deps,
	}

	return ret, nil
}

// prefix output with spdx-repo as a parsing hint. Gradle builds can print out whatever they
// want during "configuration" phase.
var initRepos = `
gradle.allprojects {
  tasks.register('spdxPrintRepos') {
    doLast {
      repositories.each { println "spdx-repo:" + it.url }
    }
  }
}
`

// collect all dependency repositories in order
func getRepositories(dir string) ([]string, error) {
	return repositories(dir, initRepos)
}

var initBuildRepos = `
gradle.allprojects {
  tasks.register('spdxPrintRepos') {
    doLast {
      buildscript.repositories.each { println "spdx-repo:" + it.descriptor.url }
    }
  }
}
`

// TODO: this doesn't differentiate between "plugin" repos and "buildscript" repos,
func getBuildRepositories(dir string) ([]string, error) {
	return repositories(dir, initBuildRepos)
}

// inject an initscript to print out all repositories
func repositories(dir string, initContents string) ([]string, error) {
	initFile, err := ioutil.TempFile("", "*-spdx-init.gradle")
	if err != nil {
		return nil, err
	}
	_, err = initFile.Write([]byte(initContents))
	if err != nil {
		return nil, err
	}
	initPath, err := filepath.Abs(initFile.Name())
	if err != nil {
		return nil, err
	}
	out, err := newGradleExec(dir).run(":spdxPrintRepos", "--init-script", initPath, "-q").CombinedOutput()
	if err != nil {
		log.Println(string(out))
	}
	return parseRepoOutput(out)
}

// ensure these are in the order they are printed, order determines where
// dependencies are resolved from
func parseRepoOutput(out []byte) ([]string, error) {
	result := []string{}
	br := bytes.NewReader(out)
	sc := bufio.NewScanner(br)

	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "spdx-repo:") {
			split := strings.SplitN(line, ":", 2)
			if len(split) != 2 {
				return nil, fmt.Errorf("Parse error on : %q", line)
			}
			result = append(result, split[1])
		}
	}
	return result, nil
}

// groupId, artifactId, version
func splitDep(dep string) (string, string, string, error) {
	parts := strings.SplitN(dep, ":", 3)
	if len(parts) != 3 {
		return "", "", "", fmt.Errorf("Dependency parse error on : %q", dep)
	}
	groupId := parts[0]
	artifactId := parts[1]
	version := parts[2]
	return groupId, artifactId, version, nil
}

// returns the path to a jar for a dependency for any valid repository
// append this to a repository url to get a dependency location
func calculateURLSuffix(dep string) (string, error) {
	groupId, artifactId, version, err := splitDep(dep)
	if err != nil {
		return "", err
	}

	groupIdPath := strings.Replace(groupId, ".", "/", -1)
	artifactName := artifactId + "-" + version
	// gradle plugins are pom pointing to jar, this is a simple hueristic to
	// handle that. It might not cover all cases though
	if strings.HasSuffix(artifactId, "gradle.plugin") {
		artifactName += ".pom"
	} else {
		artifactName += ".jar"
	}
	suffix := path.Join(groupIdPath, artifactId, version, artifactName)
	return suffix, nil
}

// apparently this is the only way to correctly merge urls
// https://stackoverflow.com/questions/34668012/combine-url-paths-with-path-join/34668130
func mergeURL(base, suffix string) (string, error) {
	url, err := url.Parse(base)
	if err != nil {
		return "", err
	}
	url.Path = path.Join(url.Path, suffix)
	return url.String(), nil
}

func findDownloadLocations(repos []string, deps []string) (map[string]string, error) {
	depUrls := map[string]string{}
	for _, dep := range deps {
		suffix, err := calculateURLSuffix(dep)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			remote, err := mergeURL(repo, suffix)
			if err != nil {
				return nil, err
			}
			if remoteExists(remote) {
				depUrls[dep] = remote
				break
			}
		}
		if _, ok := depUrls[dep]; !ok {
			return nil, fmt.Errorf("Could not find download location for %q", dep)
		}
	}
	return depUrls, nil
}

func getSHA1(depURL string) (string, error) {
	sb := make([]byte, 0, 40)

	r, err := http.Get(depURL + ".sha1")
	if err != nil {
		return "", err
	}

	defer r.Body.Close()
	if b, err := io.ReadAll(io.LimitReader(r.Body, int64(cap(sb)))); err != nil {
		return "", err
	} else {
		return string(b), nil
	}
}

func remoteExists(depURL string) bool {
	r, err := http.Head(depURL)
	if err != nil {
		log.Print(err)
		return false
	}
	return r.StatusCode == 200
}
