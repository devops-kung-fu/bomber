package cmd

import (
	"bytes"
	"encoding/json"
	"errors"
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
)

var (
	token, username, provider string
	severitySummary           = models.Summary{}
	// summary, detailed bool
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scans a provided SBoM file or folder containing SBoMs for vulnerabilities.",
		PreRun: func(cmd *cobra.Command, args []string) {
			provider = strings.ToLower(provider)
			output = strings.ToLower(output)
			if !slices.Contains([]string{"osv", "ossindex"}, provider) {
				color.Red.Printf("%s is not a valid provider type.\n\n", provider)
				_ = cmd.Help()
				os.Exit(1)
			}
			if !slices.Contains([]string{"json", "xml", "stdout"}, output) {
				color.Red.Printf("%s is not a valid output type.\n\n", output)
				_ = cmd.Help()
				os.Exit(1)
			}
			err := validateUser()
			if err != nil {
				color.Red.Println(err)
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
				s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
				util.DoIf(output == "stdout", func() {
					util.PrintInfo("Ecosystems detected:", strings.Join(ecosystems, ","))
					util.PrintInfof("Scanning %v packages for vulnerabilities...\n", len(purls))
					s.Suffix = fmt.Sprintf(" Fetching vulnerability data from %s", provider)
					s.Start()
				})

				if provider == "ossindex" {
					util.DoIf(output == "stdout", func() {
						util.PrintInfo("Vulnerability Provider:", ossindex.Info(), "\n")
					})
					response, err = ossindex.Scan(purls, username, token)
				} else {
					util.DoIf(output == "stdout", func() {
						util.PrintInfo("Vulnerability Provider:", osv.Info(), "\n")
					})
					response, err = osv.Scan(purls, username, token)
				}
				util.DoIf(output != "json", func() {
					s.Stop()
				})
				if err != nil {
					util.PrintErr(err)
					os.Exit(1)
				}
				vulnCount := 0
				var p models.Package
				var vv models.Vulnerability
				var packages []models.Package
				for _, r := range response {
					vulns := len(r.Vulnerabilities)
					vulnCount += vulns
					p = r
					if provider == "ossindex" {
						p.Vulnerabilities = nil
					}
					for _, v := range r.Vulnerabilities {
						vv = v
						if provider == "ossindex" {
							vv.Severity = ratingScale(v.CvssScore)
							p.Vulnerabilities = append(p.Vulnerabilities, vv)
						}
						adjustSummary(vv.Severity)
					}
					if vulns > 0 {
						packages = append(packages, p)
					}
				}
				err := renderOutput(packages)
				if err != nil {
					log.Println(err)
				}
				util.DoIf(output == "stdout", func() {
					if vulnCount > 0 {
						fmt.Println()
						color.Red.Printf("Total vulnerabilities found: %v\n", vulnCount)
						fmt.Println()
						renderSeveritySummary()
						fmt.Println()
						fmt.Println("NOTE: The list of vulnerabilities displayed may differ from provider to provider. This list")
						fmt.Println("may not contain all possible vulnerabilities. Please try the other providers that bomber")
						fmt.Println("supports (osv, ossindex)")
					} else if output != "json" {
						color.Green.Printf("No vulnerabilities found using the %v provider\n", provider)
						fmt.Println()
						fmt.Printf("NOTE: Just because bomber didn't find any vulnerabilities using the %v provider does\n", provider)
						fmt.Println("not mean that there are no vulnerabilities. Please try the other providers that bomber")
						fmt.Println("supports (osv, ossindex)")
					}
				})

			} else {
				util.PrintInfo("No packages were detected. Nothing has been scanned.")
			}

		},
	}
)

func validateUser() (err error) {
	if username == "" {
		username = os.Getenv("BOMBER_PROVIDER_USERNAME")
	}
	if token == "" {
		token = os.Getenv("BOMBER_PROVIDER_TOKEN")
	}
	if provider == "ossindex" {
		if username == "" && token == "" {
			err = errors.New("the OSS Index provider requires a username and token")
		}
	}
	return
}

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVar(&username, "username", "", "The user name for the provider being used.")
	scanCmd.PersistentFlags().StringVar(&token, "token", "", "The API token for the provider being used.")
	scanCmd.PersistentFlags().StringVar(&provider, "provider", "osv", "The vulnerability provider (ossindex, osv).")
}

// RenderDetails will render enhanced details of the vulnerabilities found. Not implemented yet.
// func renderDetails(response []models.Package) {
// 	t := table.NewWriter()
// 	t.SetOutputMirror(os.Stdout)
// 	t.Style().Options.DrawBorder = false
// 	t.SetColumnConfigs([]table.ColumnConfig{
// 		{
// 			Number:   2,
// 			WidthMin: 6,
// 			WidthMax: 64,
// 		},
// 	})
// 	for _, r := range response {
// 		if len(r.Vulnerabilities) > 0 {
// 			t.AppendRow([]interface{}{"Package", r.Purl})
// 			t.AppendRow([]interface{}{"Description", r.Description})
// 			t.AppendRow([]interface{}{"Vulnerabilities", fmt.Sprint(len(r.Vulnerabilities))})
// 			for _, v := range r.Vulnerabilities {
// 				t.AppendRow([]interface{}{"CVSS Score", v.CvssScore})
// 				t.AppendRow([]interface{}{"CWE", v.Cwe})
// 				t.AppendRow([]interface{}{"Description", v.Description})
// 			}
// 			t.AppendSeparator()
// 		}
// 	}
// 	t.Style().Options.SeparateRows = true
// 	t.Render()
// }

func renderSummary(response []models.Package) {
	if len(response) == 0 {
		return
	}
	log.Println("Rendering Packages:", response)
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Type", "Name", "Version", "Severity", "Vulnerability"})
	for _, r := range response {
		purl, err := packageurl.FromString(r.Purl)
		if err != nil {
			log.Println(err)
		}
		for _, v := range r.Vulnerabilities {
			t.AppendRow([]interface{}{purl.Type, purl.Name, purl.Version, v.Severity, v.ID})
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

func renderOutput(packages []models.Package) (err error) {
	if output == "stdout" {
		renderSummary(packages)
		return
	} else if output == "json" {

		output := models.Bomber{
			Meta: models.Meta{
				Version: version,
				Date:    time.Now(),
			},
			Summary:  severitySummary,
			Packages: packages,
		}

		b, err := json.Marshal(output)
		if err != nil {
			log.Println(err)
			return err
		}

		var prettyJSON bytes.Buffer
		error := json.Indent(&prettyJSON, b, "", "\t")
		if error != nil {
			log.Println("JSON parse error: ", error)
			return err
		}

		fmt.Println(string(prettyJSON.Bytes()))
	}
	return
}
