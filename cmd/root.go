// Package cmd contains all of the commands that may be executed in the cli
package cmd

import (
	"context"
	"fmt"
	"io"
	"log"
	"os"

	"github.com/google/go-github/github"
	"github.com/gookit/color"
	"github.com/spf13/afero"
	"github.com/spf13/cobra"
)

var (
	version = "0.5.0"
	output  string
	//Afs stores a global OS Filesystem that is used throughout bomber
	Afs = &afero.Afero{Fs: afero.NewOsFs()}
	//Verbose determines if the execution of hing should output verbose information
	debug   bool
	rootCmd = &cobra.Command{
		Use:     "bomber [flags] file",
		Example: "  bomber scan --output html test.cyclonedx.json",
		Short:   "Scans SBOMs for security vulnerabilities.",
		Version: version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			if !debug {
				log.SetOutput(io.Discard)
			}
			if output != "json" {
				log.Println("Start")
				fmt.Println()
				printAsciiArt()
				fmt.Println()
				fmt.Println("DKFM - DevOps Kung Fu Mafia")
				fmt.Println("https://github.com/devops-kung-fu/bomber")
				fmt.Printf("Version: %s\n", version)
				fmt.Println()
				checkForNewVersion(version)
			}
		},
	}
)

func printAsciiArt() {
	response := `
   __              __          
  / /  ___  __ _  / /  ___ ____
 / _ \/ _ \/  ' \/ _ \/ -_) __/
/_.__/\___/_/_/_/_.__/\__/_/   `
	color.Style{color.FgWhite, color.OpBold}.Println(response)
}

// Execute creates the command tree and handles any error condition returned
func Execute() {
	if err := rootCmd.Execute(); err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
}

func init() {
	rootCmd.PersistentFlags().BoolVar(&debug, "debug", false, "displays debug level log messages.")
	rootCmd.PersistentFlags().StringVar(&output, "output", "stdout", "how bomber should output findings (json, html, ai, md, stdout)")
}

func checkForNewVersion(currentVersion string) {
	ctx := context.Background()
	client := github.NewClient(nil)

	release, _, err := client.Repositories.GetLatestRelease(ctx, "devops-kung-fu", "bomber")
	if err != nil {
		log.Printf("Error fetching latest release: %v\n", err)
		return
	}

	latestVersion := release.GetTagName()[1:] // Remove leading 'v'
	if latestVersion != currentVersion {
		color.Yellow.Printf("A newer version of bomber is available (%s)\n\n", latestVersion)
	}
}
