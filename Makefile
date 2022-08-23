# HELP
# This will output the help for each task
# thanks to https://marmelab.com/blog/2016/02/29/auto-documented-makefile.html
.PHONY: help

help: ## This help
	@awk 'BEGIN {FS = ":.*?## "} /^[a-zA-Z_-]+:.*?## / {printf "\033[36m%-30s\033[0m %s\n", $$1, $$2}' $(MAKEFILE_LIST)

.DEFAULT_GOAL := help

title:
	@echo "bomber Makefile"
	@echo "---------------"

build: ## Builds the application
	go get -u ./...
	go mod tidy
	go build

test: ## Runs tests and coverage
	go test -v -coverprofile=coverage.out ./... && go tool cover -func=coverage.out

check: build ## Tests the pre-commit hooks if they exist
	hookz reset --verbose --debug --verbose-output 
	. .git/hooks/pre-commit

all: title build test ## Makes all targets