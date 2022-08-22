package cmd

import (
	"fmt"
	"os"

	"github.com/devops-kung-fu/common/util"
	"github.com/fatih/color"
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
		Run: func(cmd *cobra.Command, args []string) {
			purls, err := lib.Load(Afs, args)
			response, err := providers.OSSIndex(purls, username, token)
			util.DoIf(Verbose, func() {
				if err != nil {
					util.PrintErr(err)
					os.Exit(1)
				}
				util.PrintInfof("Scanning %v packages for vulnerabilities...\n\n", len(purls))

				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()

				tbl := table.New("purl", "description", "vulnerabilities")
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

				for _, r := range response {
					vulns := len(r.Vulnerabilities)
					tbl.AddRow(r.Coordinates, r.Description, vulns)
				}

				tbl.Print()
				fmt.Println()
				util.PrintSuccess("Done")
			})
		},
	}
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVarP(&provider, "provider", "p", "ossindex", "The provider to use when scanning.")
	rootCmd.PersistentFlags().StringVar(&username, "username", "u", "The user name of the provider being used.")
	rootCmd.PersistentFlags().StringVar(&token, "token", "t", "The API token of the provider being used.")
}
