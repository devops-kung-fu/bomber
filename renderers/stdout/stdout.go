package stdout

import (
	"fmt"
	"log"
	"os"
	"strings"

	"github.com/devops-kung-fu/common/util"
	"github.com/gookit/color"
	"github.com/jedib0t/go-pretty/v6/table"
	"github.com/package-url/packageurl-go"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render a pretty tabular summary to STDOUT
type Renderer struct{}

// Render renders a pretty tabular summary to STDOUT
func (Renderer) Render(results models.Results) (err error) {
	if len(results.Packages) == 0 {
		return
	}
	if len(results.Files) > 0 {
		util.PrintInfo("Files Scanned")
		for _, scanned := range results.Files {
			util.PrintTabbedf("%s (sha256:%s)", scanned.Name, scanned.SHA256)
		}
		fmt.Println()

	}
	if len(results.Licenses) > 0 {
		util.PrintInfo("Licenses Found:", strings.Join(results.Licenses[:], ", "))
		fmt.Println()
	}
	vulnCount := vulnerabilityCount(results.Packages)
	log.Println("Rendering Packages:", len(results.Packages))
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	rowConfigAutoMerge := table.RowConfig{AutoMerge: true}
	t.AppendHeader(table.Row{"Type", "Name", "Version", "Severity", "Vulnerability"}, rowConfigAutoMerge)
	for _, r := range results.Packages {
		purl, err := packageurl.FromString(r.Purl)
		if err != nil {
			log.Println(err)
		}
		for _, v := range r.Vulnerabilities {
			t.AppendRow([]interface{}{purl.Type, purl.Name, purl.Version, v.Severity, v.ID}, rowConfigAutoMerge)
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
	t.Render()
	if vulnCount > 0 {
		fmt.Println()
		color.Red.Printf("Total vulnerabilities found: %v\n", vulnCount)
		fmt.Println()
		renderSeveritySummary(results.Summary)
		fmt.Println()
		fmt.Println("NOTE: The list of vulnerabilities displayed may differ from provider to provider. This list")
		fmt.Println("may not contain all possible vulnerabilities. Please try the other providers that bomber")
		fmt.Println("supports (osv, ossindex)")
	} else {
		color.Green.Printf("No vulnerabilities found using the %v provider\n", results.Meta.Provider)
		fmt.Println()
		fmt.Printf("NOTE: Just because bomber didn't find any vulnerabilities using the %v provider does\n", results.Meta.Provider)
		fmt.Println("not mean that there are no vulnerabilities. Please try the other providers that bomber")
		fmt.Println("supports (osv, ossindex)")
	}
	return
}

func renderSeveritySummary(summary models.Summary) {
	log.Println("Rendering Severity Summary")
	t := table.NewWriter()
	t.SetOutputMirror(os.Stdout)
	t.AppendHeader(table.Row{"Rating", "Count"})
	t.AppendRow([]interface{}{"CRITICAL", summary.Critical})
	t.AppendRow([]interface{}{"HIGH", summary.High})
	t.AppendRow([]interface{}{"MODERATE", summary.Moderate})
	t.AppendRow([]interface{}{"LOW", summary.Low})
	if summary.Unspecified > 0 {
		t.AppendRow([]interface{}{"UNSPECIFIED", summary.Unspecified})
	}
	t.SetStyle(table.StyleRounded)
	t.Style().Options.SeparateRows = true
	t.Render()
}

func vulnerabilityCount(packages []models.Package) (vulnCount int) {
	for _, r := range packages {
		vulns := len(r.Vulnerabilities)
		vulnCount += vulns
	}
	return
}
