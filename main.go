package cmd

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"spdx-sbom-generator/cmd/generator"
)

var cmdRoot = &cobra.Command{
	Use:   "spdx-sbom-generator",
	Short: "Generates SPDX formatted documentation",
	Long:  "Generates SPDX formatted documentation",
}

func init() {
	cmdRoot.AddCommand(generator.CMD)
}

// Execute starts command
func Execute() {
	if err := cmdRoot.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}
