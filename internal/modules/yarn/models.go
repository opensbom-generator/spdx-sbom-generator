package yarn

type dependency struct {
	Name         string
	PkPath       string
	Version      string
	Resolved     string
	Integrity    string
	Dependencies []string
}
