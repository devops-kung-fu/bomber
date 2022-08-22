package main

import (
	"os"

	"github.com/devops-kung-fu/bomber/cmd"
)

func main() {
	defer os.Exit(0)
	cmd.Execute()
}
