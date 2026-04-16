# AGENTS.md

## Project overview

Open OSCAR Server is an open-source instant messaging server written in Go that
is compatible with classic AIM and ICQ clients. It implements the OSCAR, TOC,
and Kerberos protocols, plus HTTP management and web APIs. It is independent of
AOL/Yahoo and non-commercial.

## Quick commands

| Task                | Command                                                    |
|---------------------|------------------------------------------------------------|
| Build               | `go build -o open_oscar_server ./cmd/server`               |
| Test                | `go test -race ./...`                                      |
| Lint (matches CI)   | `gofmt -s -l . && go vet ./...`                            |
| Run (dev, plain)    | `make run`                                                 |
| Run (dev, SSL)      | `make run-ssl` (+ `make run-stunnel` in a second terminal) |
| Generate config     | `make config`                                              |
| Regenerate mocks    | `mockery`                                                  |
| Build Docker images | `make docker-images`                                       |

## Architecture

The binary in `cmd/server` starts five servers concurrently via `errgroup`:

| Server   | Protocol                   | Default port                        |
|----------|----------------------------|-------------------------------------|
| OSCAR    | FLAP/BOS (binary)          | 5190 (5193 via stunnel for SSL)     |
| TOC      | TOC (text-based)           | 9898                                |
| Kerberos | Kerberos auth              | 1088                                |
| MgmtAPI  | HTTP (management)          | 8080                                |
| WebAPI   | HTTP (web AIM-style, AMF3) | 9000 (opt-in via `ENABLE_WEBAPI=1`) |

All five servers share a common dependency container (`Container` in
`cmd/server/factory.go`) that wires together config, persistence, and business
logic.

## Key packages

| Package           | Role                                                                                                                                                                                                           |
|-------------------|----------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------|
| `cmd/server`      | Entry point; wires dependencies and starts all servers.                                                                                                                                                        |
| `config`          | Configuration via env vars (`envconfig`). Config files are generated from the `Config` struct—do **not** edit them by hand; run `make config` instead.                                                         |
| `foodgroup`       | Core business logic for OSCAR "food groups": Auth, Buddy, Feedbag, ICBM, Chat, BART, Locate, OService, ICQ, Admin, PermitDeny, ODir, Stats, UserLookup, ChatNav. Shared by the OSCAR, TOC, and WebAPI servers. |
| `wire`            | OSCAR wire protocol: SNAC/FLAP encoding, TLV, food group codes, rate limits, frames.                                                                                                                           |
| `state`           | Persistence and in-memory state: `SQLiteUserStore`, `InMemorySessionManager`, `InMemoryChatSessionManager`, DB migrations.                                                                                     |
| `server/oscar`    | OSCAR protocol server; SNAC routing and handler wiring.                                                                                                                                                        |
| `server/toc`      | TOC protocol server (text-based).                                                                                                                                                                              |
| `server/kerberos` | Kerberos auth server.                                                                                                                                                                                          |
| `server/http`     | Management HTTP API (users, sessions, chat rooms). Spec: `api.yml`.                                                                                                                                            |
| `server/webapi`   | Web AIM-style API (AMF3). Spec: `docs/open_api/webapi.yml`.                                                                                                                                                    |

## Database

SQLite via `modernc.org/sqlite` (pure-Go, no CGO). Default file: `oscar.sqlite`.
Migrations live in `state/migrations/` as numbered `.up.sql` / `.down.sql` pairs
and are applied automatically at startup.

## Configuration

Configuration is env-var driven via `kelseyhightower/envconfig`. Settings files
(`config/settings.env`, `config/ssl/settings.env`) are **generated** from the
`Config` struct by running `make config`. Never edit them by hand—change the
`Config` struct and regenerate.

## Testing conventions

- **Table-driven tests** — slices of structs with `name`, inputs, and expected
  outputs; iterated with `t.Run`.
- **Assertions** — `github.com/stretchr/testify/assert` (`assert.Equal`,
  `assert.NoError`, etc.).
- **Mocks** — generated by [mockery](https://github.com/vektra/mockery)
  (config in `.mockery.yaml`). Mock files are named `mock_*_test.go` and live
  next to the code they test. Regenerate with `mockery` at the repo root.
- **`mockParams` structs** — group per-test-case mock expectations; defined in
  `*_helpers_test.go` files alongside the tests.
- **Test helpers** — shared fixtures and builders live in `*_helpers_test.go`.

## Code style

- Standard Go conventions; CI enforces `gofmt -s` and `go vet`.
- Small, focused interfaces for dependency injection and testability (e.g.
  `SessionRetriever`, `FeedbagManager`).
- Doc comments on all exported symbols.
- Errors follow the standard `if err != nil` pattern; sentinel errors and custom
  error types are used where appropriate.

## OSCAR protocol reference

The [OSCAR protocol specification](https://devinsmith.net/backups/OSCAR/) covers
roughly 80% of the protocol: FLAP framing, SNAC structure, and the major food
groups (OSERVICE, BUDDY, ICBM, FEEDBAG, BART, LOCATE, PD, INVITE). The
remaining ~20% (e.g. some ICQ-specific SNACs, chat, and lesser-used food groups)
is not documented there and must be reverse-engineered from client behavior or
other sources.

## Useful docs

| Document            | Path                                                         |
|---------------------|--------------------------------------------------------------|
| Build & run         | `docs/BUILD.md`                                              |
| Management API spec | `api.yml`                                                    |
| Web API spec        | `docs/open_api/webapi.yml`                                   |
| OSCAR protocol spec | https://devinsmith.net/backups/OSCAR/                        |
| Client setup guides | `docs/CLIENT.md`, `docs/CLIENT_TIK.md`, `docs/CLIENT_ICQ.md` |
| Docker guide        | `docs/DOCKER.md`                                             |
| Platform guides     | `docs/LINUX.md`, `docs/MACOS.md`, `docs/WINDOWS.md`          |

## Go guidelines

- **Injected dependencies are non-nil** — Types that the server factory wires up receive dependency fields through their
  constructors; those fields are non-nil before the value is used. Call `dep.Method()` directly. Do not add
  `if dep != nil` guards around those calls; that implies an optional dependency and duplicates an invariant already
  enforced by construction. (Optional pointers, slices, maps, and values from external input still need normal nil/empty
  checks.)