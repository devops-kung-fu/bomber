package cmd

import (
	"fmt"
	"os"

	"github.com/devops-kung-fu/common/util"
	"github.com/fatih/color"
	goocolor "github.com/gookit/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/providers"
)

var (
	token, username string
	scanCmd         = &cobra.Command{
		Use:   "scan",
		Short: "Scans a provided SBoM file or folder containing SBoMs for vulnerabilities.",
		PreRun: func(cmd *cobra.Command, args []string) {
			if username == "" {
				username = os.Getenv("BOMBER_PROVIDER_USERNAME")
			}
			if token == "" {
				token = os.Getenv("BOMBER_PROVIDER_TOKEN")
			}
			if username == "" && token == "" {
				goocolor.Red.Println("Both a username and token are required\n")
				_ = cmd.Help()
				os.Exit(1)
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			purls, err := lib.Load(Afs, args)
			if err != nil {
				util.PrintErr(err)
				os.Exit(1)
			}
			if len(purls) > 0 {
				util.PrintInfof("Scanning %v packages for vulnerabilities...\n\n", len(purls))
			} else {
				util.PrintInfo("No valid SBOMs were detected. Nothing has been scanned")
			}

			providers.OutputCredits()
			fmt.Println()

			response, err := providers.OSSIndex(purls, username, token)
			if err != nil {
				util.PrintErr(err)
				os.Exit(1)
			}
			vulnCount := 0
			for _, r := range response {
				vulns := len(r.Vulnerabilities)
				vulnCount += vulns
			}

			if vulnCount > 0 {
				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()

				tbl := table.New("purl", "description", "vulnerabilities")
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

				for _, r := range response {
					vulns := len(r.Vulnerabilities)
					if vulns > 0 {
						tbl.AddRow(r.Coordinates, r.Description, vulns)
					}
				}

				tbl.Print()
				fmt.Println()
				goocolor.Red.Printf("Vulnerabilities found: %v\n\n", vulnCount)
			} else if vulnCount > 0 && len(response) > 0 {
				goocolor.Green.Println("No vulnerabilities found!\n")
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVar(&username, "username", "", "The user name of the provider being used.")
	scanCmd.PersistentFlags().StringVar(&token, "token", "", "The API token of the provider being used.")
}
