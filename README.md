# Retro AIM Server

<div align="center">

<a href="">[![codecov](https://codecov.io/gh/mk6i/retro-aim-server/graph/badge.svg?token=MATKPP77JT)](https://codecov.io/gh/mk6i/retro-aim-server)</a>
<a href="">[![Discord](https://img.shields.io/discord/1238648671348719626?logo=discord&logoColor=white)](https://discord.gg/2Xy4nF3Uh9)</a>

</div>

**Retro AIM Server** is an instant messaging server that revives AOL Instant Messenger clients from the 2000s.

<p align="center">
  <img width="616" alt="screenshot of retro aim server running next to AIM" src="https://github.com/mk6i/retro-aim-server/assets/2894330/81ff419f-50fa-4961-bd2f-ac7dcac903b5">
</p>

The following features are supported:

- [x] Windows AIM client v2.x, v3.x, v4.x, v5.x
- [x] Away Messages
- [x] Buddy Icons (v4.x, v5.x)
- [x] Buddy List
- [x] Chat Rooms (v4.x, v5.x)
- [x] Instant Messaging
- [x] User Profiles
- [x] Blocking (v3.5+)
- [x] Visibility Toggle / Idle Notification
- [x] Warning

## 🏁 How to Run

Get up and running with Retro AIM Server using one of these handy server quickstart guides:

* [Linux (x86_64)](./docs/LINUX.md)
* [macOS (Intel and Apple Silicon)](./docs/MACOS.md)
* [Windows 10/11 (x86_64)](./docs/WINDOWS.md)

Don't have AIM installed yet? Check out the [AIM Client Setup Guide](./docs/CLIENT.md).

## 🛠️ Development

This project is under active development. Contributions are welcome!

Follow [this guide](./docs/BUILD.md) to learn how to compile and run Retro AIM Server.

## 🌍 Community

Check out the Retro AIM Server [Discord server](https://discord.gg/2Xy4nF3Uh9) to get help or find out how to get involved.

## 👤 Management API

The Management API provides functionality for administering the server (see [OpenAPI spec](./api.yml)). The following
shows you how to run these commands via the command line.

### Windows PowerShell

> Run these commands from **PowerShell**, *not* **Command Prompt**.

#### List Users

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user -Method Get
```

#### Create Users

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user `
  -Body '{"screen_name":"myscreenname", "password":"thepassword"}' `
  -Method Post `
  -ContentType "application/json"
```

#### Change Password

```powershell
Invoke-WebRequest -Uri http://localhost:8080/user/password `
  -Body '{"screen_name":"myscreenname", "password":"thenewpassword"}' `
  -Method Put `
  -ContentType "application/json"
```

#### List Active Sessions

This request lists sessions for all logged in users.

```powershell
Invoke-WebRequest -Uri http://localhost:8080/session -Method Get
```

### macOS / Linux

#### List Users

```shell
curl http://localhost:8080/user
```

#### Create Users

```shell
curl -d'{"screen_name":"myscreenname", "password":"thepassword"}' http://localhost:8080/user
```

#### Change Password

```shell
curl -X PUT -d'{"screen_name":"myscreenname", "password":"thenewpassword"}' http://localhost:8080/user/password
```

#### List Active Sessions

This request lists sessions for all logged in users.

```shell
curl http://localhost:8080/session
```

## 🔗 Acknowledgements

- [aim-oscar-server](https://github.com/ox/aim-oscar-server) is another cool open source AIM server project.
- [NINA Wiki](https://wiki.nina.chat/wiki/Main_Page) is an indispensable source for figuring out the OSCAR API.
- [libpurple](https://developer.pidgin.im/wiki/WhatIsLibpurple) is also an invaluable OSCAR reference (especially
  version [2.10.6-1](https://github.com/Tasssadar/libpurple)).

## 📄 License

Retro AIM Server is licensed under the [MIT license](./LICENSE).
