# Development: How to Run/Compile Open OSCAR Server

This guide explains how to set up a development environment for Open OSCAR Server and build/run the application. It
assumes that you have little to no experience with golang.

## Dependencies

Before you can run Open OSCAR Server, set up the following software dependencies.

### Golang

Since Open OSCAR Server is written in go, install the latest version of [golang](https://go.dev/).

If you're new to go, try [Visual Studio Code](https://code.visualstudio.com) wth the [go plugin](https://code.visualstudio.com/docs/languages/go)
as your first IDE.

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
go build -o open_oscar_server ./cmd/server
```

To run the binary with the settings file:

```shell
./open_oscar_server -config config/settings.env
```

## Testing

Open OSCAR Server includes a test suite that must pass before merging new code. To run the unit tests, run the following
command from the root of the repository in a terminal:

```shell
go test -race ./...
```

## Config File Generation

The config file `config/settings.env` is generated programmatically from the [Config](../config/config.go) struct using
`go generate`. If you want to add or remove application configuration options, first edit the Config struct and then
generate the configuration files by running `make config` from the project root. Do not edit the config files by hand.
