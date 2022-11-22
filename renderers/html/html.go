package html

import (
	"fmt"
	"log"
	"path/filepath"
	"strings"
	"text/template"
	"time"

	"github.com/devops-kung-fu/common/util"
	"github.com/gomarkdown/markdown"
	"github.com/microcosm-cc/bluemonday"
	"github.com/spf13/afero"

	"github.com/devops-kung-fu/bomber/models"
)

// Renderer contains methods to render results to an HTMLfile
type Renderer struct{}

// Render renders results to an HTML file
func (Renderer) Render(results models.Results) (err error) {
	//TODO: Refactor the Renderer interface to take an Afero FS
	afs := &afero.Afero{Fs: afero.NewOsFs()}

	t := time.Now()
	r := strings.NewReplacer("-", "", " ", "-", ":", "-")
	filename := t.Format("2006-01-02 15:04:05")
	filename, _ = filepath.Abs(fmt.Sprintf("./%s-bomber-results.html", r.Replace(filename)))

	util.PrintInfo("Writing filename:", filename)
	err = writeTemplate(afs, filename, results)
	if err != nil {
		log.Println(err)
		return
	}
	return
}

func writeTemplate(afs *afero.Afero, filename string, results models.Results) (err error) {
	// for i, p := range results.Packages {
	// 	percentageString := "N/A"
	// 	for _, v := range p.Vulnerabilities {
	// 		per, err := strconv.ParseFloat(v.Epss.Percentile, 64)
	// 		if err != nil {
	// 			log.Println(err)
	// 		} else {
	// 			percentage := math.Round(per * 100)
	// 			if percentage > 0 {
	// 				percentageString = fmt.Sprintf("%d%%", uint64(percentage))
	// 			}
	// 		}
	// 		p.Vulnerabilities[i].Epss.Percentile = percentageString
	// 	}
	// }

	file, err := afs.Create(filename)
	if err != nil {
		log.Println(err)
		return err
	}
	markdownToHTML(results)

	template := genTemplate("output")
	err = template.ExecuteTemplate(file, "output", results)
	if err != nil {
		log.Println(err)
		return err
	}
	err = afs.Fs.Chmod(filename, 0777)
	if err != nil {
		log.Println(err)
		return err
	}

	return
}

func markdownToHTML(results models.Results) {
	for i := range results.Packages {
		for ii := range results.Packages[i].Vulnerabilities {
			md := []byte(results.Packages[i].Vulnerabilities[ii].Description)
			html := markdown.ToHTML(md, nil, nil)
			results.Packages[i].Vulnerabilities[ii].Description = string(bluemonday.UGCPolicy().SanitizeBytes(html))
		}
	}
}

func genTemplate(output string) (t *template.Template) {

	content := `

<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta http-equiv="X-UA-Compatible" content="IE=edge">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>bomber Results</title>

	<style>
	body {
		font-family: Helvetica;
		margin: 20px;
	}
	#vuln {
		border: 1px solid;
		border-color: gray;
		border-radius: 5px;
		padding: 10px;
		margin-bottom: 10px;
	}
	#bomber-logo {
		margin-top: 10px;
		margin-bottom: 10px;
		width:128px;
		height:128px;
		background-image:url(data:image/png;base64,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);
	}
	#summary {
		border: 0px;
	}
	#CRITICAL {
		color: red;
		font-weight: bold;
	}
	#HIGH {
		color: purple;
		font-weight: bold;
	}
	#MODERATE {
		color: goldenrod;
		font-weight: bold;
	}
	#LOW {
		color: green;
		font-weight: bold;
	}
	#UNSPECIFIED {
		color: blue;
		font-weight: bold;
	}
	h3 {
		font-weight: bold
	}
	#footer {
		width: 75px;
		height: 75px;
		margin-bottom: 10px;
		background-image:url(data:image/png;base64,iVBORw0KGgoAAAANSUhEUgAAAEsAAABLCAYAAAA4TnrqAAAAAXNSR0IArs4c6QAAAIRlWElmTU0AKgAAAAgABQESAAMAAAABAAEAAAEaAAUAAAABAAAASgEbAAUAAAABAAAAUgEoAAMAAAABAAIAAIdpAAQAAAABAAAAWgAAAAAAAABIAAAAAQAAAEgAAAABAAOgAQADAAAAAQABAACgAgAEAAAAAQAAAEugAwAEAAAAAQAAAEsAAAAAdzEKuAAAAAlwSFlzAAALEwAACxMBAJqcGAAAAVlpVFh0WE1MOmNvbS5hZG9iZS54bXAAAAAAADx4OnhtcG1ldGEgeG1sbnM6eD0iYWRvYmU6bnM6bWV0YS8iIHg6eG1wdGs9IlhNUCBDb3JlIDYuMC4wIj4KICAgPHJkZjpSREYgeG1sbnM6cmRmPSJodHRwOi8vd3d3LnczLm9yZy8xOTk5LzAyLzIyLXJkZi1zeW50YXgtbnMjIj4KICAgICAgPHJkZjpEZXNjcmlwdGlvbiByZGY6YWJvdXQ9IiIKICAgICAgICAgICAgeG1sbnM6dGlmZj0iaHR0cDovL25zLmFkb2JlLmNvbS90aWZmLzEuMC8iPgogICAgICAgICA8dGlmZjpPcmllbnRhdGlvbj4xPC90aWZmOk9yaWVudGF0aW9uPgogICAgICA8L3JkZjpEZXNjcmlwdGlvbj4KICAgPC9yZGY6UkRGPgo8L3g6eG1wbWV0YT4KGV7hBwAAGR1JREFUeAHVnAWUZcW1hs8M7u4QXIIEXhjkwePh7rZIkAQnggV3XQt3dx8cgjMwDO42WAgEGSS4+3T37a73f7vrP6m+dM/0zDQwb69Vt86pU7Jr17baVd39qp8extUQ/ZXalFIx3Dh6nlZpRqUZcppZ+UxKUyl9p/RhTp/k/DPlHyt9qVTCeHqh70ZZ2NfP/fq6w9wf/UKMZuTnHGeccZafcsop151gggkWHm+88aZIKU3fT9C/f/9K36q2trbqyy+/rFSn0veqo6MjkurR9feNRuOLlpaWoV999dUdqnuvyl7lQwEsTrtSuTDF59F/7GtiwUEQCS4yLK6HVaabbro1p5pqqgGiyyRvvPFGpUn7O3mHEpNzThkAfk70XeM777zzViJwiwg79KOPPrpL3+5ReljJALdBNPrsE6gH74PeQM5EYmLbKu0wyyyzLAmX/OMf//AQMYGNNtqo+u1vf9tv4okn7q/Ub4YZZug300wzVRNNNFGkH374oWptba0+/vjj6tNPP63ESam9vb3jlVdeSeeeey6E9cJUv/71r6tvv/22evfdd59W+QlK13gw5SVeRfEv8wgnkQxbSsSem3322ZMIxaRIELGxxx57tP/973/veP3115MmJ8kadZAIpjfffDPdfvvtHfvvvz+Eh0Xpv32OOeZIv/rVr5KI/6TeN1My1IR1wejkY8pZ6AfL0//q+ei55pprGUTsnXfeYQL9/vKXv4y72mqrwUWViIfo1HiKU0Ic0Uuff/453FMNHz68EgkriWsloleTTjpp6K8JJ5wwysYff/y6PQ8ffvhhcO3NN99cnX766YGLxhkXDtWiPKEqByjdS13BGHHZ6BKLdqHApYQXlaI9WKK28cwzz1y9/PLLIWYHHHDAeL///e9DRFDchm+++aYaNmxY9dxzz1VPPPFETPbrr7+uHn744SCU65X5MsssU00xxRTV1FNPXa244orVb37zm2q++eaLMtdjgV588cXquuuuq44++mgWqv/8888/DuO9//77g0Xk3SXWL6scgkFUOP4nB1jD7LGFnpO4iYEhUpsI1PHUU08lcUstY4jc0KFDk1Y+rb766hbNH+XSW2nOOedMc889d+TSYUmc+KN6jLnccsulE088MT3++ONJxK7HYlzG+tOf/oRih2iNeeaZhz5aldZXArzYnW8/0S+rYth3kkkmSQsssACItCy77LLpjjvuSN9//32N+BdffJGuvvrqtOaaa3aZMPqMduLENM000yRxTRKHdqmjPuNdXJkmm2yyJM5NsqjRLi9OXX+NNdZIN910U2I8A7rtscceS1tttRX1Whhv8skn5/lAJUM5H5f1SY5+MlwikUizzTZbrN4ZZ5yRxO7GM8mSJemQNGDAgHpCcA0Iq02P3CI9lZqTBqz7KJ9nnXXWJDELhe5y6cV04403djEe0oG2nm0zzjhjB9yq+jcvvvjiJlQ5L30ac4gOp5122snU1W1YHeWweLt0RC1y0l1JeijtuOOO9QQRgemnnx4LVZepXRCFfFQTxCzbyAgEx2VRi2+bbLJJuvvuuxPcZbj11lv5hqpozXWHymjMpXfAhOt8G4PfIJSs0nTq45UsAi16DsIYGVmzdOihh9YTWXDBBUO8qNc8Qcp6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);}
	</style>
</head>
<body>
	<div id="bomber-logo"></div>
	<h1>bomber Results</h1>
	<p>The following results were detected by <code>{{.Meta.Generator}} {{.Meta.Version}}</code> on {{.Meta.Date}} using the {{.Meta.Provider}} provider.</p>
	{{ if ne (len .Packages) 0 }} 
	<p>
		Vulnerabilities displayed may differ from provider to provider. This list may not contain all possible vulnerabilities. Please try the other providers that <code>bomber</code> supports (osv, ossindex, snyk). There is no guarantee that 
		the next time you scan for vulnerabilities that there won't be more, or less of them. Threats are continuous.
	</p>
	<p>
		For more information on EPSS % and probability of exploitation, please refer to <a href="https://www.first.org/epss/">https://www.first.org/epss/"</a>.</p>
	</p>
	{{ else }}
	<p>
		No vulnerabilities found!
	</p>
	{{ end }}
	{{ if ne (len .Files) 0 }} 
		<h1>Scanned Files</h1>
		{{ range .Files }}
			<p><b>{{ .Name }}</b> (sha256:{{ .SHA256 }})</p>
		{{ end }}
	{{end}}
	{{ if ne (len .Licenses) 0 }} 
		<h1>Licenses</h1>
		<p>The following licenses were found by <code>bomber</code>:</p>
		<ul>
		{{ range $license := .Licenses }}
			<li>{{ $license }}</li>
		{{ end }}
		</ul>
	{{ else }}
		<p>No license information detected.</b>
	{{ end }}
	{{ if ne (len .Packages) 0 }} 
		<h1>Vulnerability Summary</h1>
		<table id="summary">
			<tr><td>Critical:</td><td>{{ .Summary.Critical }}</td></tr>
			<tr><td>High:</td><td>{{ .Summary.High }}</td></tr>
			<tr><td>Moderate:</td><td>{{ .Summary.Moderate }}</td></tr>
			<tr><td>Low:</td><td>{{ .Summary.Low }}</td></tr>
			<tr><td>Unspecified:</td><td>{{ .Summary.Unspecified }}</td></tr>
		</table>
		<h1>Vulnerability Details</h1>
		{{ range .Packages }}
			<h2>{{ .Purl }}</h2>
			<p>{{ .Description }}</p>
			<h3>Vulnerabilities</h3>
			{{ range .Vulnerabilities }}
				<div id="vuln">
					{{ if .Title }}
					<h3>{{ .Title }}</h3>
					{{ end }}
					<p>Severity: <span id="{{ .Severity }}">{{ .Severity }}</span></p>
					{{ if ne (len .Epss.Percentile) 0 }} 
						<p>EPSS %: <span>{{ .Epss.Percentile }}</span></p>
					{{ end }}
					<p><a href="{{ .Reference }}">Reference Documentation</a></p>
					<p>{{ .Description }}
				</div>
			{{ end }}
			<br/>
		{{ end }}
	{{ end }}
	<div id="footer"></div>
	Powered by the <a href="https://github.com/devops-kung-fu"/>DevOps Kung Fu Mafia</a>
</body>
</html>

`
	return template.Must(template.New(output).Parse(content))
}
