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
	"github.com/package-url/packageurl-go"
	"github.com/spf13/cobra"
	"k8s.io/utils/strings/slices"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/lib/enrichment"
	"github.com/devops-kung-fu/bomber/lib/filters"
	"github.com/devops-kung-fu/bomber/models"
	"github.com/devops-kung-fu/bomber/providers"
	"github.com/devops-kung-fu/bomber/renderers"
)

var (
	providerName    string
	severitySummary = models.Summary{}
	credentials     = models.Credentials{}
	renderer        models.Renderer
	provider        models.Provider
	ignoreFile      string

	// summary, detailed bool
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scans a provided SBoM file or folder containing SBoMs for vulnerabilities.",
		PreRun: func(cmd *cobra.Command, args []string) {
			r, err := renderers.NewRenderer(output)
			if err != nil {
				color.Red.Printf("%v\n\n", err)
				_ = cmd.Help()
				os.Exit(1)
			}
			renderer = r
			p, err := providers.NewProvider(providerName)
			if err != nil {
				color.Red.Printf("%v\n\n", err)
				_ = cmd.Help()
				os.Exit(1)
			}
			provider = p
		},
		Run: func(cmd *cobra.Command, args []string) {
			scanned, purls, licenses, err := lib.Load(Afs, args)
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
						util.PrintErr(err)
						log.Println(err)
					}
					if !slices.Contains(ecosystems, purl.Type) {
						ecosystems = append(ecosystems, purl.Type)
					}
				}
				s := spinner.New(spinner.CharSets[9], 100*time.Millisecond)
				util.DoIf(output != "json", func() {
					util.PrintInfo("Ecosystems detected:", strings.Join(ecosystems, ","))
					util.PrintInfof("Scanning %v packages for vulnerabilities...\n", len(purls))
					util.PrintInfo("Vulnerability Provider:", provider.Info(), "\n")
					s.Suffix = fmt.Sprintf(" Fetching vulnerability data from %s", providerName)
					s.Start()
				})

				response, err = provider.Scan(purls, &credentials)
				if err != nil {
					log.Print(err)
				}
				ignoredCVE, err := lib.LoadIgnore(Afs, ignoreFile)
				if err != nil {
					util.PrintWarningf("Ignore flag set, but there was an error: %s", err)
				}

				for i, p := range response {
					enrichedVulnerabilities, _ := enrichment.Enrich(p.Vulnerabilities)
					response[i].Vulnerabilities = enrichedVulnerabilities

					if len(ignoredCVE) > 0 {
						filteredVulnerabilities := filters.Ignore(p.Vulnerabilities, ignoredCVE)
						response[i].Vulnerabilities = filteredVulnerabilities
					}
				}

				util.DoIf(output != "json", func() {
					s.Stop()
				})
				if err != nil {
					util.PrintErr(err)
					os.Exit(1)
				}
				vulnCount := 0
				for _, r := range response {
					vulns := len(r.Vulnerabilities)
					vulnCount += vulns
					for _, v := range r.Vulnerabilities {
						lib.AdjustSummary(v.Severity, &severitySummary)
					}
				}
				results := models.NewResults(response, severitySummary, scanned, licenses, version, providerName)
				err = renderer.Render(results)
				if err != nil {
					log.Println(err)
				}

			} else {
				util.PrintInfo("No packages were detected. Nothing has been scanned.")
			}
			log.Println("Finished")
		},
	}
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVar(&credentials.Username, "username", "", "The user name for the provider being used.")
	scanCmd.PersistentFlags().StringVar(&credentials.Token, "token", "", "The API token for the provider being used.")
	scanCmd.PersistentFlags().StringVar(&providerName, "provider", "osv", "The vulnerability provider (ossindex, osv).")
	scanCmd.PersistentFlags().StringVar(&ignoreFile, "ignore-file", "", "An optional file containing CVEs to ignore when rendering output.")
}
