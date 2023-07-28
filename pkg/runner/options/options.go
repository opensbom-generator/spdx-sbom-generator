// SPDX-License-Identifier: Apache-2.0

package options

import (
	"github.com/opensbom-generator/parsers/cargo"
	"github.com/opensbom-generator/parsers/composer"
	"github.com/opensbom-generator/parsers/gem"
	"github.com/opensbom-generator/parsers/go"
	"github.com/opensbom-generator/parsers/gradle"
	"github.com/opensbom-generator/parsers/maven"
	"github.com/opensbom-generator/parsers/npm"
	"github.com/opensbom-generator/parsers/nuget"
	"github.com/opensbom-generator/parsers/pip"
	"github.com/opensbom-generator/parsers/plugin"
	"github.com/opensbom-generator/parsers/swift"
	"github.com/opensbom-generator/parsers/yarn"
)

const (
	OutputFormatSpdx OutputFormat = iota
	OutputFormatJson
)

var DefaultPlugins = []plugin.Plugin{cargo.New(),
	composer.New(),
	gomod.New(),
	gem.New(),
	npm.New(),
	javagradle.New(),
	javamaven.New(),
	nuget.New(),
	yarn.New(),
	pip.New(),
	swift.New()}

type Options struct {
	SchemaVersion     string // SPDX Version
	Indent            int
	Version           string
	License           bool
	Depth             string
	Slug              string
	OutputDir         string
	Schema            string
	Format            OutputFormat
	GlobalSettingFile string
	Path              string
	Plugins           []plugin.Plugin
}

type OutputFormat int

func (o OutputFormat) String() string {
	switch o {
	case 0:
		return "spdx"
	case 1:
		return "json"
	default:
		return ""
	}
}

var Default = Options{
	Plugins: DefaultPlugins,
}
