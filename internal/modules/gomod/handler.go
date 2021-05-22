package gomod

import (
	"bytes"
	"crypto/sha1"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os/exec"
	"path"
	"path/filepath"
	"strings"

	"spdx-sbom-generator/internal/helper"
	"spdx-sbom-generator/internal/models"
)

type mod struct {
	metadata models.PluginMetadata
}

// New ...
func New() *mod {
	return &mod{
		metadata: models.PluginMetadata{
			Name:       "Go Modules",
			Slug:       "go-mod",
			Manifest:   "go.mod",
			ModulePath: "vendor",
		},
	}
}

// GetMetadata ...
func (m *mod) GetMetadata() models.PluginMetadata {
	return m.metadata
}

// IsValid ...
func (m *mod) IsValid(path string) bool {
	return helper.FileExists(filepath.Join(path, m.metadata.Manifest))
}

// HasModulesInstalled ...
func (m *mod) HasModulesInstalled(path string) bool {
	return helper.FileExists(filepath.Join(path, m.metadata.ModulePath))
}

// GetVersion...
func (m *mod) GetVersion() (string, error) {
	cmd := exec.Command("go", "version")
	output, err := cmd.Output()
	if err != nil {
		return "", err
	}

	fields := strings.Fields(string(output))
	if len(fields) != 4 {
		return "", fmt.Errorf("expected four fields in output, but got %d: %s", len(fields), output)
	}

	if fields[0] != "go" || fields[1] != "version" {
		return "", fmt.Errorf("unexpected output format: %s", output)
	}

	return fields[2], nil
}

// GetModule...
func (m *mod) GetModule(path string) ([]models.Module, error) {
	buf := new(bytes.Buffer)
	if err := helper.ExecCMD(path, buf, "go", "list", "-mod", "readonly", "-json", "-m"); err != nil {
		return nil, fmt.Errorf("listing modules failed: %w", err)
	}
	defer buf.Reset()

	return parseModules(buf)
}

// ListModules...
func (m *mod) ListModules(path string) ([]models.Module, error) {
	buf := new(bytes.Buffer)
	if err := helper.ExecCMD(path, buf, "go", "list", "-mod", "readonly", "-json", "-m", "all"); err != nil {
		return nil, fmt.Errorf("listing modules failed: %w", err)
	}
	defer buf.Reset()

	return parseModules(buf)
}

// ListAllModules ...
func (m *mod) ListAllModules(path string) ([]models.Module, error) {

	var modules []models.Module
	var err error

	buf := new(bytes.Buffer)
	if err := helper.ExecCMD(path, buf, "go", "list", "-mod", "readonly", "-json", "-m", "all"); err != nil {
		return nil, fmt.Errorf("listing modules failed: %w", err)
	}

	defer buf.Reset()
	modules, err = parseModules(buf)
	if err != nil {
		return nil, fmt.Errorf("parsing modules failed: %w", err)
	}

	//Add Dependencies

	return modules, nil
}

// parseModules parses the output of `go list -json -m` into a Module slice
func parseModules(reader io.Reader) ([]models.Module, error) {
	modules := make([]models.Module, 0)
	jsonDecoder := json.NewDecoder(reader)

	// Output is not a JSON array, so we have to parse one object after another
	for {
		var mod models.Module
		if err := jsonDecoder.Decode(&mod); err != nil {
			if errors.Is(err, io.EOF) {
				break
			}
			return nil, err
		}
		mod.Name = path.Base(mod.Path)
		mod.PackageURL = genUrl(mod)
		mod.CheckSum = &models.CheckSum{
			Algorithm: models.HashAlgoSHA1,
			Value:     readCheckSum(mod.Path),
		}
		modules = append(modules, mod)
	}
	return modules, nil
}

func genUrl(m models.Module) string {
	path := m.Path + "@" + m.Version
	if m.Version == "" {
		path = m.Path
	}

	return "pkg:golang/" + path
}

// this is just a test
func readCheckSum(content string) string {
	h := sha1.New()
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}
