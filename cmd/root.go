// Package cmd contains all of the commands that may be executed in the cli
package cmd

import (
	"fmt"
	"io/ioutil"
	"log"
	"os"

	"github.com/devops-kung-fu/common/util"
	"github.com/gookit/color"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	version = "0.1.1"
	output  string
	//Afs stores a global OS Filesystem that is used throughout bomber
	Afs = &afero.Afero{Fs: afero.NewOsFs()}
	//Verbose determines if the execution of hing should output verbose information
	debug   bool
	rootCmd = &cobra.Command{
		Use:     "bomber [flags] file",
		Example: "  bomber test.spdx",
		Short:   "Scans SBoMs for security vulnerabilities.",
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !debug {
				log.SetOutput(ioutil.Discard)
			}
			util.DoIf(output != "json", func() {
				fmt.Println()
				color.Style{color.FgWhite, color.OpBold}.Println(" ██▄ ▄▀▄ █▄ ▄█ ██▄ ██▀ █▀▄")
				color.Style{color.FgWhite, color.OpBold}.Println(" █▄█ ▀▄▀ █ ▀ █ █▄█ █▄▄ █▀▄")
				fmt.Println()
				fmt.Println("DKFM - DevOps Kung Fu Mafia")
				fmt.Println("https://github.com/devops-kung-fu/bomber")
				fmt.Printf("Version: %s\n", version)
				fmt.Println()
			})
		},
	}
)

// Execute creates the command tree and handles any error condition returned
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "Displays debug level log messages.")
	rootCmd.PersistentFlags().StringVar(&output, "output", "stdout", "How bomber should output findings (json, xml, stdout)")
}
