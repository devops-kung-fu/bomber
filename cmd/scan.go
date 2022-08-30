package cmd

import (
	"fmt"
	"log"
	"os"
	"strings"
	"time"

	"github.com/briandowns/spinner"
	"github.com/devops-kung-fu/common/util"
	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/jedib0t/go-pretty/v6/text"
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"k8s.io/utils/strings/slices"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/models"
	ossindex "github.com/devops-kung-fu/bomber/providers/ossindex"
	"github.com/devops-kung-fu/bomber/providers/osv"
	"github.com/devops-kung-fu/bomber/providers/snyk"
)

var (
	token, username, provider string
	severitySummary           = models.SeveritySummary{}
	// summary, detailed bool
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scans a provided SBoM file or folder containing SBoMs for vulnerabilities.",
		PreRun: func(cmd *cobra.Command, args []string) {
			//TODO: make sure the provider is valid or barf out
			if username == "" {
				username = os.Getenv("BOMBER_PROVIDER_USERNAME")
			}
			if token == "" {
				token = os.Getenv("BOMBER_PROVIDER_TOKEN")
			}
			if provider == "ossindex" {
				if username == "" && token == "" {
					color.Red.Println("The OSS Index provider requires a username and token\n")
					_ = cmd.Help()
					os.Exit(1)
				}
			} else if provider == "snyk" {
				if token == "" {
					color.Red.Println("The Snyk provider requires a token\n")
					_ = cmd.Help()
					os.Exit(1)
				}
			}
		},
		Run: func(cmd *cobra.Command, args []string) {
			purls, err := lib.Load(Afs, args)
			if err != nil {
				util.PrintErr(err)
				os.Exit(1)
			}
			if len(purls) > 0 {
				var response []models.Package

				ecosystems := []string{}
				for _, p := range purls {
					purl, err := packageurl.FromString(p)
					if err != nil {
						log.Println(err)
					}
					if !slices.Contains(ecosystems, purl.Type) {
						ecosystems = append(ecosystems, purl.Type)
					}
				}
				util.PrintInfo("Ecosystems detected:", strings.Join(ecosystems, ","))
				util.PrintInfof("Scanning %v packages for vulnerabilities...\n", len(purls))
				s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
				s.Suffix = fmt.Sprintf(" Fetching vulnerability data from %s", provider)
				s.Start()
				if provider == "snyk" {
					util.PrintInfo("Vulnerability Provider:", snyk.Info(), "\n")
					response, err = snyk.Scan(purls, username, token)
				} else if provider == "ossindex" {
					util.PrintInfo("Vulnerability Provider:", ossindex.Info(), "\n")
					response, err = ossindex.Scan(purls, username, token)
				} else {
					util.PrintInfo("Vulnerability Provider:", osv.Info(), "\n")
					response, err = osv.Scan(purls, username, token)
				}
				s.Stop()
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
					RenderSummary(response)
					fmt.Println()
					color.Red.Printf("Vulnerabilities found: %v\n\n", vulnCount)
					renderSeveritySummary()
					fmt.Println()
					fmt.Println("NOTE: The list of vulnerabilities displayed may differ from provider to provider. This list")
					fmt.Println("may not contain all possible vulnerabilities. Please try the other providers that bomber")
					fmt.Println("supports (osv, ossindex, snyk)")
				} else {
					color.Green.Printf("No vulnerabilities found using the %v provider\n", provider)
					fmt.Println()
					fmt.Printf("NOTE: Just because bomber didn't find any vulnerabilities using the %v provider does\n", provider)
					fmt.Println("not mean that there are no vulnerabilities. Please try the other providers that bomber")
					fmt.Println("supports (osv, ossindex, snyk)")
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
	scanCmd.PersistentFlags().StringVar(&provider, "provider", "osv", "The vulnerability provider (ossindex, snyk, osv).")
}

// RenderDetails will render enhanced details of the vulnerabilities found. Not implemented yet.
func RenderDetails(response []models.Package) {
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
			t.AppendRow([]interface{}{"Package", r.Purl})
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

func RenderSummary(response []models.Package) {
	log.Println("Rendering Packages:", response)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Type", "Name", "Version", "Severity", "Vulnerability"})
	for _, r := range response {
		if len(r.Vulnerabilities) > 0 {
			purl, err := packageurl.FromString(r.Purl)
			if err != nil {
				log.Println(err)
			}
			for _, v := range r.Vulnerabilities {
				if provider == "ossindex" {
					v.Severity = ratingScale(v.CvssScore)
				}
				adjustSummary(v.Severity)
				t.AppendRow([]interface{}{purl.Type, purl.Name, purl.Version, v.Severity, v.Cwe})
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
	})
	t.Style().Options.SeparateRows = true
	t.Style().Format.Header = text.FormatDefault
	t.Style().Color.Header = text.Colors{text.Bold}
	t.Render()
}

func renderSeveritySummary() {
	log.Println("Rendering Severity Summary")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Rating", "Count"})
	t.AppendRow([]interface{}{"CRITICAL", severitySummary.Critical})
	t.AppendRow([]interface{}{"HIGH", severitySummary.High})
	t.AppendRow([]interface{}{"MODERATE", severitySummary.Moderate})
	t.AppendRow([]interface{}{"LOW", severitySummary.Low})
	if severitySummary.None > 0 {
		t.AppendRow([]interface{}{"NONE", severitySummary.None})
	}
	t.SetStyle(table.StyleRounded)
	t.Style().Options.SeparateRows = true
	t.Style().Format.Header = text.FormatDefault
	t.Style().Color.Header = text.Colors{text.Bold}
	t.Render()
}

func ratingScale(score float64) string {
	if score > 0 && score <= 3.9 {
		return "LOW"
	} else if score >= 4.0 && score <= 6.9 {
		return "MODERATE"
	} else if score >= 7.0 && score <= 8.9 {
		return "HIGH"
	} else if score >= 9.0 && score <= 10.0 {
		return "CRITICAL"
	}
	return "NONE"
}

func adjustSummary(severity string) {
	switch severity {
	case "LOW":
		severitySummary.Low++
	case "MODERATE":
		severitySummary.Moderate++
	case "HIGH":
		severitySummary.High++
	case "CRITICAL":
		severitySummary.Critical++
	default:
		severitySummary.None++
	}
}
