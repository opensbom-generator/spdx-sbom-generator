// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"strings"

	"github.com/gookit/color"
	"github.com/i582/cfmt/cmd/cfmt"
	log "github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"spdx-sbom-generator/internal/handler"
)

const jsonLogFormat = "json"
const defaultLogLevel = "info"

// provided through ldflags on build
var (
	version string
)

var errRequiredEnVarError = errors.New("environment variable required")

var rootCmd = &cobra.Command{
	Use:   "spdx-sbom-generator",
	Short: "Output Package Manager dependency on SPDX format",
	Long:  "Output Package Manager dependency on SPDX format",
	Run:   generate,
}

func main() {
	if version == "" {
		version = "source-code"
	}

	if err := rootCmd.Execute(); err != nil {
		log.Fatal(err)
	}
}
func init() {
	rootCmd.Flags().StringP("path", "p", ".", "the path to package file or the path to a directory which will be recursively analyzed for the package files (default '.')")
	rootCmd.Flags().BoolP("include-license-text", "i", false, " Include full license text (default: false)")
	rootCmd.Flags().StringP("schema", "s", "2.2", "<version> Target schema version (default: '2.2')")
	rootCmd.Flags().StringP("output-dir", "o", ".", "<output> directory to Write SPDX to file (default: current directory)")
	rootCmd.Flags().StringP("format", "f", "spdx", "output file format (default: spdx)")

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
	cfmt.Printf(`
{{                                                       }}::bgBlue
{{               Starting to generate SBOM file          }}::bgBlue|#ffffff
{{                                                       }}::bgBlue
`)
	checkOpt := func(opt string) string {
		cmdOpt, err := cmd.Flags().GetString(opt)
		if err != nil {
			log.Fatalf("Failed to read command option %v", err)
		}

		return cmdOpt
	}
	path := checkOpt("path")
	outputDir := checkOpt("output-dir")
	schema := checkOpt("schema")
	format := checkOpt("format")
	license, err := cmd.Flags().GetBool("include-license-text")
	if err != nil {
		log.Fatalf("Failed to read command option: %v", err)
	}

	cfmt.Println()
	cfmt.Println(cfmt.Sprintf("{{CLI version: }}::cyan|bold %s", color.Yellow.Sprintf(version)))
	cfmt.Println(cfmt.Sprintf("{{Directory to analyze: }}::cyan|bold %s", color.Yellow.Sprintf(path)))
	cfmt.Println(cfmt.Sprintf("{{Output Format: }}::cyan|bold %s", color.Yellow.Sprintf(strings.ToUpper(format))))
	handler, err := handler.NewSPDX(handler.SPDXSettings{
		Version:   version,
		Path:      path,
		License:   license,
		OutputDir: outputDir,
		Schema:    schema,
		Format:    format,
	})
	if err != nil {
		log.Fatalf("Failed to initialize command: %v", err)
	}

	if err := handler.Run(); err != nil {
		log.Fatalf("Failed to run command: %v", err)
	}

	handler.Complete()
}
