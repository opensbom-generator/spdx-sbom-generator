// package plugin provides the plugin interface for generating SPDX SBOMs
package plugin

import (
	"errors"

	"github.com/spdx/tools-golang/spdx/common"
)

// Plugin is the interface a plugin must implement
// GetSpdxDocument returns an object of type AnyDocument
type Plugin interface {
	GetSpdxDocument() (common.AnyDocument, error)
}

// plugins stores a mapping of the plugin name and its
// corresponding Plugin object
var plugins = make(map[string]Plugin)

// Register registers a plugin by name
// A plugin can use this function to create a plugin entry in their
// init function
func Register(name string, p Plugin) {
	if p == nil {
		panic("A Plugin object is required, but is nil")
	}
	if _, dup := plugins[name]; dup {
		panic("Register called twice for plugin name " + name)
	}
	plugins[name] = p
}

// GetPlugin takes the name of a plugin and returns the
// Plugin object for that plugin
func GetPlugin(name string) (Plugin, error) {
	p := plugins[name]
	if p == nil {
		return nil, errors.New("No plugin registered with name " + name)
	} else {
		return p, nil
	}
}
