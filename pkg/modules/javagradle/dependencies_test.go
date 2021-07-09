// SPDX-License-Identifier: Apache-2.0

package javagradle

import (
	"io/ioutil"
	"reflect"
	"sort"
	"testing"
)

func TestParseDependencyOutput(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/dependencies.out")
	if err != nil {
		t.Fatal(err)
	}
	di, err := parseDependencyOutput(data)
	if err != nil {
		t.Fatal(err)
	}

	{
		want := map[string][]string{
			"antlr:antlr:2.7.7": {},
			"com.google.cloud.tools:appengine-plugins-core:0.9.1": {
				"com.google.guava:guava:28.2-jre",
				"org.yaml:snakeyaml:1.21",
				"com.google.code.gson:gson:2.8.6",
				"org.glassfish:javax.json:1.0.4",
				"org.apache.commons:commons-compress:1.20",
			},
			"com.google.code.gson:gson:2.8.6":      {},
			"com.google.guava:failureaccess:1.0.1": {},
			"com.google.guava:guava:27.0.1-jre": {
				"com.google.guava:failureaccess:1.0.1",
			},
			"com.google.guava:guava:28.2-jre": {
				"com.google.guava:failureaccess:1.0.1",
			},
			"com.puppycrawl.tools:checkstyle:8.18": {
				"info.picocli:picocli:3.9.5",
				"antlr:antlr:2.7.7",
				"org.antlr:antlr4-runtime:4.7.2",
				"commons-beanutils:commons-beanutils:1.9.3",
				"com.google.guava:guava:27.0.1-jre",
				"net.sf.saxon:Saxon-HE:9.9.1-1",
			},
			"commons-beanutils:commons-beanutils:1.9.3": {
				"commons-collections:commons-collections:3.2.2",
			},
			"commons-collections:commons-collections:3.2.2": {},
			"info.picocli:picocli:3.9.5":                    {},
			"net.sf.saxon:Saxon-HE:9.9.1-1":                 {},
			"org.antlr:antlr4-runtime:4.7.2":                {},
			"org.apache.commons:commons-compress:1.20":      {},
			"org.glassfish:javax.json:1.0.4":                {},
			"org.yaml:snakeyaml:1.21":                       {},
		}
		if reflect.DeepEqual(di.graph, want) == false {
			t.Fatalf("\n got: %q\nwant: %q", di.graph, want)
		}
	}
	{
		want := []string{
			"com.google.cloud.tools:appengine-plugins-core:0.9.1",
			"com.puppycrawl.tools:checkstyle:8.18",
		}
		sorted := di.root
		sort.Strings(sorted)
		if reflect.DeepEqual(sorted, want) == false {
			t.Fatalf("\n got: %q\nwant: %q", sorted, want)
		}
	}
	{
		want := []string{
			"antlr:antlr:2.7.7",
			"com.google.cloud.tools:appengine-plugins-core:0.9.1",
			"com.google.code.gson:gson:2.8.6",
			"com.google.guava:failureaccess:1.0.1",
			"com.google.guava:guava:27.0.1-jre",
			"com.google.guava:guava:28.2-jre",
			"com.puppycrawl.tools:checkstyle:8.18",
			"commons-beanutils:commons-beanutils:1.9.3",
			"commons-collections:commons-collections:3.2.2",
			"info.picocli:picocli:3.9.5",
			"net.sf.saxon:Saxon-HE:9.9.1-1",
			"org.antlr:antlr4-runtime:4.7.2",
			"org.apache.commons:commons-compress:1.20",
			"org.glassfish:javax.json:1.0.4",
			"org.yaml:snakeyaml:1.21",
		}
		sorted := di.all
		sort.Strings(sorted)
		if reflect.DeepEqual(sorted, want) == false {
			t.Fatalf("\n got: %q\nwant: %q", sorted, want)
		}
	}

}

func TestParseRepoOutput(t *testing.T) {
	data, err := ioutil.ReadFile("testdata/repositories.out")
	if err != nil {
		t.Fatal(err)
	}
	repos, err := parseRepoOutput(data)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{
		"https://repo.maven.apache.org/maven2/",
		"https://jcenter.bintray.com/",
	}
	if reflect.DeepEqual(repos, want) == false {
		t.Fatalf("\n got: %q\nwant: %q", repos, want)
	}
}

func TestCalculateURLSuffix(t *testing.T) {
	out, err := calculateURLSuffix("com.loosebazooka:artifact1:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	want := "com/loosebazooka/artifact1/1.0.0/artifact1-1.0.0.jar"
	if out != want {
		t.Fatalf("\n got: %v\nwant: %v", out, want)
	}
}

func TestCalculateURLSuffixPlugin(t *testing.T) {
	out, err := calculateURLSuffix("com.loosebazooka:artifact.gradle.plugin:1.0.0")
	if err != nil {
		t.Fatal(err)
	}
	want := "com/loosebazooka/artifact.gradle.plugin/1.0.0/artifact.gradle.plugin-1.0.0.pom"
	if out != want {
		t.Fatalf("\n got: %v\nwant: %v", out, want)
	}
}

func TestFindDownloadLocations(t *testing.T) {
	repos := []string{"https://repo.maven.apache.org/maven2", "https://plugins.gradle.org/m2"}
	deps := []string{"com.google.guava:guava:10.0", "com.google.cloud.tools:com.google.cloud.tools.jib.gradle.plugin:1.0.0"}
	locs, err := findDownloadLocations(repos, deps)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]string{
		"com.google.guava:guava:10.0":                                           "https://repo.maven.apache.org/maven2/com/google/guava/guava/10.0/guava-10.0.jar",
		"com.google.cloud.tools:com.google.cloud.tools.jib.gradle.plugin:1.0.0": "https://plugins.gradle.org/m2/com/google/cloud/tools/com.google.cloud.tools.jib.gradle.plugin/1.0.0/com.google.cloud.tools.jib.gradle.plugin-1.0.0.pom",
	}
	if reflect.DeepEqual(locs, want) == false {
		t.Fatalf("\n got: %v\nwant: %v", locs, want)
	}
}
