![](img/bomber128x128.png)

# bomber
[![](https://img.shields.io/badge/Status-BETA-yellow)](CONTRIBUTING.md)
![GitHub release (latest by date)](https://img.shields.io/github/v/release/devops-kung-fu/bomber) 
[![Go Report Card](https://goreportcard.com/badge/github.com/devops-kung-fu/bomber)](https://goreportcard.com/report/github.com/devops-kung-fu/bomber) 
[![codecov](https://codecov.io/gh/devops-kung-fu/bomber/branch/main/graph/badge.svg?token=P9WBOBQTOB)](https://codecov.io/gh/devops-kung-fu/bomber) 
[![SBOM](https://img.shields.io/badge/SPDX-SBoM-informational)](sbom/bomber.spdx.json)
[![SBOM](https://img.shields.io/badge/CyloneDX-SBoM-informational)](sbom/bomber.cyclonedx.json)
[![SBOM](https://img.shields.io/badge/Syft-SBoM-informational)](sbom/bomber.syft.json)

```bomber``` is an application that scans SBoMs for security vulnerabilities.

## Overview

So you've asked a vendor for an Software Bill of Materials (SBOM) for one of their products, and they provided one to you in a JSON file... now what? 

The first thing you're going to want to do is see if any of the components listed inside the SBOM have security vulnerabilities. This will help you identify what kind of risk you will be taking on by using the product. Finding security vulnerabilities for components identified in an SBOM is exactly what ```bomber``` is meant to do. It can read any JSON based [SPDX](https://spdx.dev), [CycloneDX](https://cyclonedx.org), or [Syft](https://github.com/anchore/syft) formatted SBOM and tell you pretty quickly if there are any vulnerabilities. 

Powered by the [Sonatype OSS Index](https://ossindex.sonatype.org), ```bomber``` can tell you what the component is used for, how many vulnerabilities it has, and what they are.

All you need is to download and install ```bomber``` and get yourself a free account for accessing the [Sonatype OSS Index](https://ossindex.sonatype.org).

### What SBOM formats are supported?

There are quite a few SBOM formats available today. ```bomber``` supports the following:

- [SPDX](https://spdx.dev)
- [CycloneDX](https://cyclonedx.org)
- [Syft](https://github.com/anchore/syft)

### What ecosystems are supported?

Since ```bomber``` uses the [Sonatype OSS Index](https://ossindex.sonatype.org), it will give results for the ecosystems that it supports. At this time, the following can be scanned with ```bomber```

- Maven
- NPM
- Go
- PyPi
- Nuget
- RubyGems
- Cargo
- CocoaPods
- Composer
- Conan
- Conda
- CRAN
- RPM
- Swift

## Prerequisites

In order to use ```bomber``` you need to get an account for the [Sonatype OSS Index](https://ossindex.sonatype.org). Head over to the site, and create a free account, and make note of your ```username``` (this will be the email that you registered with). 

Once you log in, you'll want to navigate to your [settings](https://ossindex.sonatype.org/user/settings) and make note of your API ```token```. **Please don't share your token with anyone. **

## Installation

### Mac

You can use [Homebrew](https://brew.sh) to install ```bomber``` using the following:

``` bash
brew tap devops-kung-fu/homebrew-tap
brew install devops-kung-fu/homebrew-tap/bomber
```

If you do not have Homebrew, you can still [download the latest release](https://github.com/devops-kung-fu/hookz/releases) (ex: ```bomber_0.1.0_darwin_all.tar.gz```), extract the files from the archive, and use the ```bomber``` binary.  

If you wish, you can move the ```bomber``` binary to your ```/usr/local/bin``` directory or anywhere on your path.

### Linux

To install ```bomber```,  [download the latest release](https://github.com/devops-kung-fu/hookz/releases) for your platform and install locally. For example, install ```bomber``` on Ubuntu:

```bash
dpkg -i bomber_0.1.0_linux_arm64.deb
```




## Using bomber

Now that we've installed ```bomber``` and have our ```username``` and ```token``` from the [Sonatype OSS Index](https://ossindex.sonatype.org), we can scan an SBOM for vulnerabilities.

You can scan either an entire folder of SBOMs or an individual SBOM with ```bomber```.  ```bomber``` doesn't care if you have multiple formats in a single folder. It'll sort everything out for you.

### Single SBOM scan

``` bash
bomber scan --username=xxx --token=xxx spdx-sbom.json
```

If there are vulnerabilities you'll see an output similar to the following:

![](img/bomber-example.png)

If the [Sonatype OSS Index](https://ossindex.sonatype.org) doesn't return any vulnerabilities you'll see something like the following:

![](img/bomber-example-novulns.png)

### Entire folder scan

This is good for when you receive multiple SBOMs from a vendor for the same product. Or, maybe you want to find out what vulnerabilities you have in your entire organization. A folder scan will find all components, de-duplicate them, and then scan them for vulnerabilities.

```bash
# scan a folder of SBOMs (the following command will scan a folder in your current folder named "sboms")
bomber scan --username=xxx --token=xxx ./sboms
```

You'll see a similar result to what a Single SBOM scan will provide.

### Advanced stuff

If you wish, you can set two environment variables to store your credentials, and not have to type them on the command line. Check out the [Environment Variables](####Environment-Variables) information later in this README.

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

### Testing

#### Environment Variables

The testing framework is set up to use environment variables that are found in a file called ```test.env``` in the **root directory** of the project. This file has been added to the ```.gitignore``` file in this project so it will be ignored if it exists in your file structure when committing the code. If you are running tests, this file should exist and have the following values configured:

``` bash
BOMBER_PROVIDER_USERNAME={{your OSS Index user name}}
BOMBER_PROVIDER_TOKEN={{your OSS Index API Token}}
```
To load this file, you use the following command in your terminal before opening an editor such as Visual Studio Code (from your terminal).

``` bash
  export $(cat *.env)
```

## Software Bill of Materials

```bomber``` uses the CycloneDX and SPDX to generate a Software Bill of Materials every time a developer commits code to this repository (as long as [Hookz](https://github.com/devops-kung-fu/hookz)is being used and is has been initialized in the working directory). More information for CycloneDX is available [here](https://cyclonedx.org). SPDX information is available [here](https://spdx.dev).

The current CycloneDX SBoM for ```bomber``` is available [here](bomber-cyclonedx-sbom.json), and the SPDX formatted SBoM is available [here](bomber-spdx-sbom.json).

## Credits

A big thank-you to our friends at [Smashicons](https://www.flaticon.com/authors/smashicons) for the ```bomber``` logo.

Big kudos to our OSS homies at [Sonatype](https://sonatype.com) for providing a wicked tool like the [Sonatype OSS Index](https://ossindex.sonatype.org).
