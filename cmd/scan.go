package cmd

import (
	"fmt"
	"os"

	"github.com/devops-kung-fu/common/util"
	"github.com/fatih/color"
	"github.com/rodaine/table"
	"github.com/spf13/cobra"

	"github.com/devops-kung-fu/bomber/lib"
)

var (
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scans a provided SBoM file or folder containing SBoMs for vulnerabilities.",
		Run: func(cmd *cobra.Command, args []string) {
			purls, err := lib.Load(Afs, args)
			util.DoIf(Verbose, func() {
				if err != nil {
					util.PrintErr(err)
					os.Exit(1)
				}
				util.PrintInfof("Scanning %v packages for vulnerabilities...\n\n", len(purls))

				headerFmt := color.New(color.FgGreen, color.Underline).SprintfFunc()
				columnFmt := color.New(color.FgYellow).SprintfFunc()

				tbl := table.New("purl")
				tbl.WithHeaderFormatter(headerFmt).WithFirstColumnFormatter(columnFmt)

				for _, r := range purls {
					tbl.AddRow(r)
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
}
