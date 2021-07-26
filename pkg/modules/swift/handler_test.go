// SPDX-License-Identifier: Apache-2.0

package swift

import (
	"fmt"
	"os/exec"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSwift(t *testing.T) {
	t.Run("test is valid", TestIsValid)
	t.Run("test has modules installed", TestHasModulesInstalled)
	t.Run("test get root module", TestGetRootModule)
	t.Run("test list used modules", TestListUsedModules)
	t.Run("test list modules with dependencies", TestListModulesWithDeps)
}

func TestIsValid(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	valid := n.IsValid(path)
	invalid := n.IsValid(getPath())

	// Assert
	assert.Equal(t, true, valid)
	assert.Equal(t, false, invalid)
}

func TestHasModulesInstalled(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())

	installed := n.HasModulesInstalled(path)
	assert.NoError(t, installed)
	uninstalled := n.HasModulesInstalled(getPath())
	assert.Error(t, uninstalled)
}

func TestGetRootModule(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mod, err := n.GetRootModule(path)

	assert.NoError(t, err)
	assert.Equal(t, "Example", mod.Name)
	assert.Equal(t, "MIT", mod.LicenseConcluded)
}

func TestListUsedModules(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListUsedModules(path)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {
		if mod.Name == "DeckOfPlayingCards" {
			assert.Equal(t, "3.0.4", mod.Version)
			assert.Equal(t, "https://github.com/apple/example-package-deckofplayingcards", mod.PackageURL)
			assert.Equal(t, "git+https://github.com/apple/example-package-deckofplayingcards.git", mod.PackageDownloadLocation)
			count++
			continue
		}

		if mod.Name == "FisherYates" {
			assert.Equal(t, "2.0.6", mod.Version)
			assert.Equal(t, "https://github.com/apple/example-package-fisheryates", mod.PackageURL)
			assert.Equal(t, "git+https://github.com/apple/example-package-fisheryates.git", mod.PackageDownloadLocation)
			count++
			continue
		}

		if mod.Name == "PlayingCard" {
			assert.Equal(t, "3.0.5", mod.Version)
			assert.Equal(t, "https://github.com/apple/example-package-playingcard", mod.PackageURL)
			assert.Equal(t, "git+https://github.com/apple/example-package-playingcard.git", mod.PackageDownloadLocation)
			count++
			continue
		}
	}

	assert.Equal(t, 3, count)
}

func TestListModulesWithDeps(t *testing.T) {
	n := New()
	path := fmt.Sprintf("%s/test", getPath())
	mods, err := n.ListModulesWithDeps(path)

	assert.NoError(t, err)

	count := 0
	for _, mod := range mods {
		if mod.Name == "Example" {
			count++
			continue
		}

		if mod.Name == "DeckOfPlayingCards" {
			assert.Equal(t, "3.0.4", mod.Version)
			assert.Equal(t, "https://github.com/apple/example-package-deckofplayingcards", mod.PackageURL)
			assert.Equal(t, "git+https://github.com/apple/example-package-deckofplayingcards.git", mod.PackageDownloadLocation)
			count++
			continue
		}
	}

	assert.Equal(t, 2, count)
}

func getPath() string {
	cmd := exec.Command("pwd")
	output, err := cmd.Output()
	if err != nil {
		return ""
	}
	path := strings.TrimSuffix(string(output), "\n")

	return path
}
