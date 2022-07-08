![](img/bomber128x128.png)

# bomber
[![](https://img.shields.io/badge/Status-UNSTABLE-orange)](CONTRIBUTING.md)
[![GoDoc](https://godoc.org/github.com/devops-kung-fu/bomber?status.svg)](https://pkg.go.dev/github.com/devops-kung-fu/bomber)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/devops-kung-fu/bomber) 
[![Go Report Card](https://goreportcard.com/badge/github.com/devops-kung-fu/bomber)](https://goreportcard.com/report/github.com/devops-kung-fu/bomber) 
[![codecov](https://codecov.io/gh/devops-kung-fu/bomber/branch/main/graph/badge.svg?token=P9WBOBQTOB)](https://codecov.io/gh/devops-kung-fu/bmber) 
[![SBOM](https://img.shields.io/badge/CyloneDX-SBoM-informational)](bomber-cyclonedx-sbom.json)
[![SBOM](https://img.shields.io/badge/SPDX-SBoM-informational)](bomber-spdx-sbom.json)

```bomber``` is a go module that converts between SPDX and CycloneDX formats

## Development

### Overview

In order to use contribute and participate in the development of ```bomber``` you'll need to have an updated Go environment. Before you start, please view the [Contributing](CONTRIBUTING.md) and [Code of Conduct](CODE_OF_CONDUCT.md) files in this repository.

### Prerequisites

This project makes use of [DKFM](https://github.com/devops-kung-fu) tools such as [Hookz](https://github.com/devops-kung-fu/hookz), [Hinge](https://github.com/devops-kung-fu/hinge), and other open source tooling. Install these tools with the following commands:

``` bash
go install github.com/devops-kung-fu/hookz@latest
go install github.com/devops-kung-fu/hinge@latest
go install github.com/kisielk/errcheck@latest
go install golang.org/x/lint/golint@latest
go install github.com/fzipp/gocyclo@latest
```
### Getting Started

Once you have installed [Hookz](https://github.com/devops-kung-fu/hookz) and have cloned this repository, execute the following in the root directory:

``` bash
hookz init --verbose --debug --verbose-output
```
This will configure the ```pre-commit``` hooks to check code quality, tests, update all dependencies, etc. before code gets committed to the remote repository.

### Building

Use the [Makefile](Makefile) to build, test, or do pre-commit checks.

Remember that this is a go module, so there is no entry point. You can execute any test function though in your preferred IDE.


## Software Bill of Materials

```bomber``` uses the CycloneDX and SPDX to generate a Software Bill of Materials every time a developer commits code to this repository (as long as [Hookz](https://github.com/devops-kung-fu/hookz)is being used and is has been initialized in the working directory). More information for CycloneDX is available [here](https://cyclonedx.org). SPDX information is available [here](https://spdx.dev).

The current CycloneDX SBoM for ```bomber``` is available [here](bomber-cyclonedx-sbom.json), and the SPDX formatted SBoM is available [here](bomber-spdx-sbom.json).

## Credits

A big thank-you to our friends at [Smashicons](https://www.flaticon.com/authors/smashicons) for the ```bomber``` logo.