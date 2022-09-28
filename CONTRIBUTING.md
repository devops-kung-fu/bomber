# Contributing to bomber

## We Develop with Github

We use github to host code, to track issues and feature requests, as well as accept pull requests.

## Use GPG to Sign Your Commits

Only pull requests that have been signed will be accepted.  For more information on setting up a GPG key for your Github account see the instructions [here](https://help.github.com/en/articles/managing-commit-signature-verification).

## Contributing Code

All Code Changes Happen Through Pull Requests.  Pull requests are the best way to propose changes to the codebase. We actively welcome your pull requests and review regularly.  We practice a single trunk development method.

- Fork the repo and create your branch from main.
- All code requires test coverage. 100% coverage is the target Add new or modify existing tests.
- If you've changed APIs, update the documentation.
- Ensure the tests pass.
- Make sure your code lints (go)
- Create a pull request.

## Licensing Notes

Any contributions you make will be under the MIT Software License. When you submit code changes, your submissions are understood to be under the same MIT License that covers the project. Feel free to contact the maintainers if that's a concern.

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

### Debugging

The project is set up to work really well with [Visual Studio Code](https://code.visualstudio.com). Once you open the ```bomber``` folder in Visual Studio Code, go ahead and use the debugger to run any one of the pre-set configurations. They are all hooked into the test SBOM's that come with the source code.

### Building

Use the [Makefile](Makefile) to build, test, or do pre-commit checks.

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
