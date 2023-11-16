// Package lib contains core functionality to load Software Bill of Materials and contains common functions
package lib

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestSetupSpinner(t *testing.T) {
	// Create a mock Scanner instance
	scanner := Scanner{}

	// Call the setupSpinner function
	spinner := scanner.setupSpinner([]string{"ecosystem1", "ecosystem2"}, []string{"package1", "package2"})

	// Assert that the returned spinner is not nil
	assert.NotNil(t, spinner, "Expected non-nil spinner, got nil")
}

// func TestExitWithCodeIfRequired(t *testing.T) {

// 	_ = os.Exit

// 	// Create a mock Scanner instance
// 	scanner := &Scanner{
// 		ExitCode: true,
// 	}

// 	// Mock results with a specific severity
// 	severitySummary := models.Summary{
// 		Unspecified: 1,
// 		Low:         2,
// 		Moderate:    3,
// 		High:        4,
// 		Critical:    5,
// 	}

// 	results := models.Results{
// 		Summary: severitySummary,
// 	}

// 	// Mock the log.Printf function
// 	var logOutput string
// 	log.SetOutput(&mockLogger{&logOutput})

// 	// Call the exitWithCodeIfRequired method
// 	scanner.exitWithCodeIfRequired(results)

// 	// Assert the log output contains the expected message
// 	require.Contains(t, logOutput, "fail severity: 5", "Log output does not contain expected message")
// }

// // mockLogger is a simple implementation of io.Writer to capture log output
// type mockLogger struct {
// 	output *string
// }

// func (m *mockLogger) Write(p []byte) (n int, err error) {
// 	*m.output += string(p)
// 	return len(p), nil
// }
