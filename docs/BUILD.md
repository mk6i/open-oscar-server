# Development: How to Run/Compile Retro AIM Server

This guide explains how to set up a development environment for Retro AIM Server and build/run the application. It
assumes that you have little to no experience with golang.

## Dependencies

Before you can run Retro AIM Server, set up the following software dependencies.

### Golang

Since Retro AIM Server is written in go, install the latest version of [golang](https://go.dev/).

If you're new to go, try [Visual Studio Code](https://code.visualstudio.com) wth the
[go plugin](https://code.visualstudio.com/docs/languages/go) as your first IDE.

### C Compiler

A C compiler is required in order to build the sqlite dependency.

#### macOS

> If you have git, this is likely already set up on your machine.

```shell
xcode-select --install
```

#### Linux (Ubuntu)

```shell
sudo apt install build-essential
```

#### Windows

Install the [tdm-gcc compiler](https://jmeubank.github.io/tdm-gcc/).

### Mockery (optional)

[Mockery](https://github.com/vektra/mockery) is used to generate test mocks. Install this dependency and regenerate the
mocks if you change any interfaces.

```shell
go install github.com/vektra/mockery/v2@latest
```

Run the following command in a terminal from the root of the repository in order to regenerate test mocks,

```shell
mockery
```

## Run the Server

To run the server using `go run`, run the following script from the root of the repository. The default settings can be
modified in `config/settings.env`.

```shell
scripts/run_dev.sh
```

## Build the Server

To build the server binary:

```shell
go build -o retro_aim_server ./cmd/server
```

To run the binary with the settings file:

```shell
source config/settings.env
./retro_aim_server
```

## Testing

Retro AIM Server includes a test suite that must pass before merging new code. To run the unit tests, run the following
command from the root of the repository in a terminal:

```shell
go test -race ./...
```

## Config File Generation

The config files `config/settings.bat` and `config/settings.env` are generated programmatically from the
[Config](../config/config.go) struct using `go generate`. If you want to add or remove application configuration
options, first edit the Config struct and then generate the configuration files by running `make config` from the
project root. Do not edit the config files by hand.
