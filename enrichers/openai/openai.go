// package openai enriches vulnerability information
package openai

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"log"
	"os"
	"text/template"

	openai "github.com/sashabaranov/go-openai"

	"github.com/devops-kung-fu/bomber/models"
)

// Provider represents the openai enricher
type Enricher struct{}

// Enrich adds additional information to vulnerabilities
func (Enricher) Enrich(vulnerabilities []models.Vulnerability, credentials *models.Credentials) ([]models.Vulnerability, error) {
	if err := validateCredentials(credentials); err != nil {
		return nil, fmt.Errorf("could not validate openai credentials: %w", err)
	}
	var enrichedVulnerabilities []models.Vulnerability
	for _, v := range vulnerabilities {
		enriched := fetch(v, credentials)
		enrichedVulnerabilities = append(enrichedVulnerabilities, enriched)
	}
	return enrichedVulnerabilities, nil
}

func validateCredentials(credentials *models.Credentials) (err error) {
	if credentials == nil {
		return errors.New("credentials cannot be nil")
	}

	if credentials.OpenAIAPIKey == "" {
		credentials.OpenAIAPIKey = os.Getenv("OPENAI_API_KEY")
	}

	if credentials.OpenAIAPIKey == "" {
		err = errors.New("bomber requires an openai key to enrich vulnerability data")
	}
	return
}

func fetch(vulnerability models.Vulnerability, credentials *models.Credentials) models.Vulnerability {
	log.Printf("OpenAI: Enriching %s", vulnerability.Cve)
	prompt := generatePrompt(vulnerability)
	client := openai.NewClient(credentials.OpenAIAPIKey)
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT4Turbo20240409,
			Messages: []openai.ChatCompletionMessage{
				{
					Role:    openai.ChatMessageRoleUser,
					Content: prompt,
				},
			},
		},
	)

	if err != nil {
		log.Printf("ChatCompletion error: %v\n", err) //TODO: Need to pass the error back up the stack
	}
	vulnerability.Explanation = resp.Choices[0].Message.Content
	return vulnerability

}

func generatePrompt(vulnerability models.Vulnerability) (prompt string) {
	promptTemplate := `
		Explain what {{ .Cve }} is and dig into: {{ .Description }} so it could be understood by a non-technical business user.
	`
	tmpl, _ := template.New("prompt").Parse(promptTemplate)

	var resultBuffer bytes.Buffer
	_ = executeTemplate(&resultBuffer, tmpl, vulnerability)

	return resultBuffer.String()
}

func executeTemplate(buffer *bytes.Buffer, tmpl *template.Template, data interface{}) error {
	return tmpl.Execute(buffer, data)
}
