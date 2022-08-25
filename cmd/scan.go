package cmd

import (
	"fmt"
	"log"
	"os"

	"github.com/devops-kung-fu/common/util"
	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/providers"
)

var (
	token, username string
	// summary, detailed bool
	scanCmd = &cobra.Command{
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
				color.Red.Println("Both a username and token are required\n")
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
				util.PrintInfof("Scanning %v packages for vulnerabilities...\n", len(purls))
				util.PrintInfo("Vulnerability Provider:", providers.OutputCredits(), "\n")

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
					// if summary {
					RenderSummary(response)
					// } else if detailed {
					// RenderDetails(response)
					// }
					fmt.Println()
					color.Red.Printf("Vulnerabilities found: %v\n\n", vulnCount)
				} else {
					color.Green.Println("No vulnerabilities found!\n")
				}
			} else {
				util.PrintInfo("No packages were detected. Nothing has been scanned.")
			}

		},
	}
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVar(&username, "username", "", "The user name of the provider being used.")
	scanCmd.PersistentFlags().StringVar(&token, "token", "", "The API token of the provider being used.")
	// rootCmd.PersistentFlags().BoolVar(&summary, "summary", false, "Displays a summary of any findings.")
	// rootCmd.PersistentFlags().BoolVar(&detailed, "detailed", false, "Displays detailed vulnerability findings.")
}

func RenderDetails(response providers.CoordinateResponses) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.Style().Options.DrawBorder = false
	t.SetColumnConfigs([]table.ColumnConfig{
		{
			Number:   2,
			WidthMin: 6,
			WidthMax: 64,
		},
	})
	for _, r := range response {
		if len(r.Vulnerabilities) > 0 {
			t.AppendRow([]interface{}{"Package", r.Coordinates})
			t.AppendRow([]interface{}{"Description", r.Description})
			t.AppendRow([]interface{}{"Vulnerabilities", fmt.Sprint(len(r.Vulnerabilities))})
			for _, v := range r.Vulnerabilities {
				t.AppendRow([]interface{}{"CVSS Score", v.CvssScore})
				t.AppendRow([]interface{}{"CWE", v.Cwe})
				t.AppendRow([]interface{}{"Description", v.Description})
			}
			t.AppendSeparator()
		}
	}
	t.Style().Options.SeparateRows = true
	t.Render()
}

func RenderSummary(response providers.CoordinateResponses) {
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Type", "Name", "Version", "Severity", "Vulnerability"})
	for _, r := range response {
		if len(r.Vulnerabilities) > 0 {
			purl, err := packageurl.FromString(r.Coordinates)
			if err != nil {
				log.Println(err)
			}
			for _, v := range r.Vulnerabilities {
				t.AppendRow([]interface{}{purl.Type, purl.Name, purl.Version, v.CvssScore, v.Cwe})
			}
		}
	}
	t.SetStyle(table.StyleRounded)
	t.SetColumnConfigs([]table.ColumnConfig{
		{
			Name:     "Description",
			WidthMin: 6,
			WidthMax: 64,
		},
	})
	t.SortBy([]table.SortBy{
		{Name: "Name", Mode: table.Dsc},
		{Name: "Severity", Mode: table.Dsc},
	})
	t.SetColumnConfigs([]table.ColumnConfig{
		{Number: 1, AutoMerge: true},
		{Number: 2, AutoMerge: true},
		{Number: 3, AutoMerge: true},
	})
	t.Style().Options.SeparateRows = true
	t.Style().Format.Header = text.FormatDefault
	t.Style().Color.Header = text.Colors{text.Bold}
	t.Render()
}
