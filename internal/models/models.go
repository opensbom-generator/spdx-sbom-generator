package models

import (
	"fmt"
)

// IPlugin ...
type IPlugin interface {
	GetVersion() (string, error)
	GetMetadata() PluginMetadata
	GetModule(path string) ([]Module, error)
	ListModules(path string) ([]Module, error)
	ListAllModules(path string) ([]Module, error)
	IsValid(path string) bool
	HasModulesInstalled(path string) error
}

// PluginMetadata ...
type PluginMetadata struct {
	Name       string
	Slug       string
	Manifest   []string
	ModulePath []string
}

// Module ... ...
type Module struct {
	Version          string `json:"Version,omitempty"`
	Name             string
	Path             string `json:"Path,omitempty"`
	LocalPath        string `json:"Dir,noempty"`
	Supplier         SupplierContact
	PackageURL       string
	CheckSum         *CheckSum
	PackageHomePage  string
	LicenseConcluded string
	LicenseDeclared  string
	CommentsLicense  string
	OtherLicense     []*License
	Copyright        string
	PackageComment   string
	Root             bool
	Modules          map[string]*Module
}

// SupplierContact ...
type SupplierContact struct {
	Type  TypeContact
	Name  string
	Email string
}

// TypeContact ...
type TypeContact string

const (
	Person       TypeContact = "Person"
	Organization TypeContact = "Organization"
)

type CheckSum struct {
	Algorithm HashAlgorithm
	Value     string
}

func (c *CheckSum) String() string {
	return fmt.Sprintf("%v: %s", c.Algorithm, c.Value)
}

// HashAlgorithm ...
type HashAlgorithm string

const (
	HashAlgoSHA1   HashAlgorithm = "SHA1"
	HashAlgoSHA224 HashAlgorithm = "SHA-224"
	HashAlgoSHA256 HashAlgorithm = "SHA-256"
	HashAlgoSHA384 HashAlgorithm = "SHA-384"
	HashAlgoSHA512 HashAlgorithm = "SHA-512"
	HashAlgoMD2    HashAlgorithm = "MD2"
	HashAlgoMD4    HashAlgorithm = "MD4"
	HashAlgoMD5    HashAlgorithm = "MD5"
	HashAlgoMD6    HashAlgorithm = "MD6"
)

// License ...
type License struct {
	ID            string
	Name          string
	ExtractedText string
	Comments      string
	File          string
}
