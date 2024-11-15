package cmd

import (
	"log"
	"os"
	"slices"
	"strings"

	"github.com/devops-kung-fu/common/util"
	"github.com/gookit/color"
	"github.com/spf13/cobra"

	"github.com/devops-kung-fu/bomber/lib"
	"github.com/devops-kung-fu/bomber/providers"
	"github.com/devops-kung-fu/bomber/renderers"
)

var (
	scanner lib.Scanner

	// summary, detailed bool
	scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Scans a provided SBOM file or folder containing SBOMs for vulnerabilities.",
		PreRun: func(cmd *cobra.Command, args []string) {
			if slices.Contains(strings.Split(output, ","), "ai") && !slices.Contains(scanner.Enrichment, "openai") {
				scanner.Enrichment = append(scanner.Enrichment, "openai")
			}
			r, err := renderers.NewRenderer(output)
			if err != nil {
				color.Red.Printf("%v\n\n", err)
				_ = cmd.Help()
				os.Exit(1)
			}
			scanner.Renderers = r
			p, err := providers.NewProvider(scanner.ProviderName)
			if err != nil {
				color.Red.Printf("%v\n\n", err)
				_ = cmd.Help()
				os.Exit(1)
			}
			scanner.Provider = p
		},
		Run: func(cmd *cobra.Command, args []string) {
			scanner.Version = version
			scanner.Output = output
			scanner.Afs = Afs
			code, err := scanner.Scan(args)
			if err != nil {
				util.PrintErr(err)
				os.Exit(1)
			}

			log.Println("Finished")
			os.Exit(code)
		},
	}
)

func init() {
	rootCmd.AddCommand(scanCmd)
	scanCmd.PersistentFlags().StringVar(&scanner.Credentials.Username, "username", "", "the user name for the provider being used.")
	scanCmd.PersistentFlags().StringVar(&scanner.Credentials.ProviderToken, "token", "", "the API token for the provider being used.")
	scanCmd.PersistentFlags().StringVar(&scanner.Credentials.OpenAIAPIKey, "openai-api-key", "", "an OpenAI API key used for generating AI output. AI Reports are EXPERIMENTAL.")
	scanCmd.PersistentFlags().StringVar(&scanner.ProviderName, "provider", "osv", "the vulnerability provider (ossindex, osv, snyk, github).")
	scanCmd.PersistentFlags().StringVar(&scanner.IgnoreFile, "ignore-file", "", "an optional file containing CVEs to ignore when rendering output.")
	scanCmd.PersistentFlags().StringVar(&scanner.Severity, "severity", "", "anything equal to or above this severity will be returned with non-zero error code.")
	scanCmd.PersistentFlags().BoolVar(&scanner.ExitCode, "exitcode", false, "if set will return an exit code representing the highest severity detected.")
	scanCmd.Flags().StringSliceVar(&scanner.Enrichment, "enrich", nil, "Enrich data with additional fields (epss, openai (EXTREMELY EXPERIMENTATL)")
}
