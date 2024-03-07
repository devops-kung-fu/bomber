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

	for _, v := range vulnerabilities {
		fetch(v, credentials)
		log.Println(v.Explanation)
	}
	return nil, nil
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

func fetch(vulnerability models.Vulnerability, credentials *models.Credentials) {
	prompt := generatePrompt(vulnerability)
	client := openai.NewClient(credentials.OpenAIAPIKey)
	resp, err := client.CreateChatCompletion(
		context.Background(),
		openai.ChatCompletionRequest{
			Model: openai.GPT3Dot5Turbo,
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
		return
	}

	vulnerability.Explanation = resp.Choices[0].Message.Content
	log.Println(vulnerability.Explanation)

}

func generatePrompt(vulnerability models.Vulnerability) (prompt string) {

	promptTemplate := `
		Explain what {{ .Cve }} is and dig into: {{ .Description }} so it could be understood by a non-technical business user.
	`
	// Create a new template with a name
	tmpl, err := template.New("prompt").Parse(promptTemplate)
	if err != nil {
		panic(err)
	}

	// Create a buffer to store the generated result
	var resultBuffer bytes.Buffer

	// Execute the template and write the result to the buffer
	err = executeTemplate(&resultBuffer, tmpl, vulnerability)
	if err != nil {
		panic(err)
	}

	// Convert the buffer to a string and return it
	return resultBuffer.String()
}

func executeTemplate(buffer *bytes.Buffer, tmpl *template.Template, data interface{}) error {
	// Execute the template and write the result to the buffer
	return tmpl.Execute(buffer, data)
}
