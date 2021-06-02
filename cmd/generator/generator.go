<<<<<<< HEAD
=======
// SPDX-License-Identifier: Apache-2.0

>>>>>>> 5072eeb001df6167e0477590fd617b5aa3bd45cb
package main

import (
	"errors"
	"os"

	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"spdx-sbom-generator/internal/handler"
)

const jsonLogFormat = "json"
const defaultLogLevel = "info"

var errRequiredEnVarError = errors.New("environment variable required")

var version string

var rootCmd = &cobra.Command{
	Use:   "spdx-sbom-generator",
	Short: "Output Package Manager dependency on SPDX format",
	Long:  "Output Package Manager dependency on SPDX format",
	Run:   generate,
}

func main() {
	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}

func init() {
	rootCmd.Flags().StringVarP(&version, "version", "v", "", "output the version number")
	rootCmd.Flags().StringP("path", "p", ".", "the path to package file or the path to a directory which will be recursively analyzed for the package files (default '.')")
	rootCmd.Flags().BoolP("include-license-text", "i", false, " Include full license text (default: false)")
	rootCmd.Flags().StringP("include-depth", "d", "all", "Dependency level (default: all) i.e 0,1,2,3,4 etc")
	rootCmd.Flags().StringP("output", "o", "bom.spdx", "<output> Write SPDX to file (default: '.spdx')")
	rootCmd.Flags().StringP("schema", "s", "2.2", "<version> Target schema version (default: '2.2')")
	//rootCmd.MarkFlagRequired("path")
	cobra.OnInitialize(setupLogger)
}

func setupLogger() {
	log.SetFormatter(&log.TextFormatter{
		ForceColors:   true,
		FullTimestamp: true,
	})
	if os.Getenv("LOG_FORMAT") == jsonLogFormat {
		log.SetFormatter(&log.JSONFormatter{})
	}

	level := os.Getenv("LOG_LEVEL")
	if level == "" {
		level = defaultLogLevel
	}

	logLevel, err := log.ParseLevel(level)
	if err != nil {
		logLevel = log.DebugLevel
	}

	log.SetLevel(logLevel)
}

func generate(cmd *cobra.Command, args []string) {
	log.Info("Starting to generate SPDX ...")
	var version string
	checkOpt := func(opt string) string {
		cmdOpt, err := cmd.Flags().GetString(opt)
		if err != nil {
			log.Fatalf("Failed to read command option %v", err)
		}

		return cmdOpt
	}
	path := checkOpt("path")
	depth := checkOpt("include-depth")
	output := checkOpt("output")
	schema := checkOpt("schema")
	license, err := cmd.Flags().GetBool("include-license-text")
	if err != nil {
		log.Fatalf("Failed to read command option: %v", err)
	}

	handler, err := handler.NewSPDX(handler.SPDXSettings{
		Version: version,
		Path:    path,
		License: license,
		Depth:   depth,
		Output:  output,
		Schema:  schema,
	})
	if err != nil {
		log.Fatalf("Failed to initialize command: %v", err)
	}

	if err := handler.Run(); err != nil {
		log.Fatalf("Failed to run command: %v", err)
	}

	handler.Complete()
}
