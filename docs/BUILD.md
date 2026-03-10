# Development: How to Run/Compile Open OSCAR Server

This guide explains how to set up a development environment for Open OSCAR Server and build/run the application. It
assumes that you have little to no experience with golang.

## Dependencies

Before you can run Open OSCAR Server, set up the following software dependencies.

### Golang

Since Open OSCAR Server is written in go, install the latest version of [golang](https://go.dev/).

If you're new to go, try [Visual Studio Code](https://code.visualstudio.com) with
the [go plugin](https://code.visualstudio.com/docs/languages/go)
as your first IDE.

### Mockery (optional)

[Mockery](https://github.com/vektra/mockery) is used to generate test mocks. Install this dependency and regenerate the
mocks if you change any interfaces.

```shell
go install github.com/vektra/mockery/v3@latest
```

Run the following command in a terminal from the root of the repository in order to regenerate test mocks,

```shell
mockery
```

## Building the Server Binary

To build the server binary:

```shell
go build -o open_oscar_server ./cmd/server
```

To run the binary with the settings file:

```shell
./open_oscar_server -config config/settings.env
```

## Running the Server

This project provides configuration for running with plain sockets and SSL sockets. Choose the mode that best suits
your needs.

### Plain Socket Config (most common)

To run AIM v1.0-v6.1, you can use the plain socket config (located in `config/settings.env`) with no additional
dependencies.

```shell
make run
```

### SSL Socket Config (for AIM v6.2-v7.0)

To run AIM v6.2-v7.0, you must run the server with SSL enabled. This project provides tooling for generating a
self-signed certificate and fronting the server with the SSL proxy [stunnel](https://www.stunnel.org/downloads.html).

#### Prerequisites

- Git
- [Docker Desktop](https://docs.docker.com/get-started/get-docker/)
- Unix-like terminal with Make installed (use WSL2 for Windows)

#### 1. Clone the Repository

```bash
git clone https://github.com/mk6i/open-oscar-server.git
cd open-oscar-server
```

#### 2. Build Docker Images

This builds Docker images for:

- Certificate generation
- SSL termination
- The Open OSCAR Server runtime

```bash
make docker-images
```

#### 3. Configure SSL Certificate

The following creates a self-signed certificate under `certs/server.pem`.

```bash
make docker-cert OSCAR_HOST=ras.dev
```

Replace `ras.dev` with the hostname clients will use to connect.

#### 4. Generate NSS Certificate Database

This creates the [NSS certificate database](https://developer.mozilla.org/en-US/docs/Mozilla/Projects/NSS) in
`certs/nss/`, which must be installed on each AIM 6.2+ client.

```bash
make docker-nss
```

#### 5. Start Open OSCAR Server

Start the server in a terminal.

```bash
make run-ssl
```

#### 6. Start stunnel

In a separate terminal, start stunnel.

```bash
make run-stunnel
```

#### 7. Client Configuration

##### Certificate Database

Follow the [AIM 6.x client setup instructions](AIM_6_7.md#aim-6265312-setup) to install the `certs/nss/` database on
each client.

##### Resolving Hostname

If `OSCAR_HOST` (e.g., `ras.dev`) is not a real domain with DNS configured, you'll need to add it to each client's hosts
file so clients can resolve it.

- Linux/macOS: `/etc/hosts`
- Windows: `C:\Windows\System32\drivers\etc\hosts`

Add a line like this, replacing the IP with your server's IP address:

```
127.0.0.1 ras.dev
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

## Setting Up Test Clients (optional)

Windows XP is the most convenient OS for running Windows OSCAR clients, which were released across the 1990s, 2000s,
and 2010s. An ISO of the most recent version is available on [archive.org](https://archive.org/details/WinXPProSP3x86).

To run Windows XP on your modern machine, install a hypervisor:

- [UTM](https://mac.getutm.app/) (macOS)
- [QEMU w/ KVM](https://www.qemu.org/) (Linux)
- [VirtualBox](https://www.virtualbox.org/) (Windows)
