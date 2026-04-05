# ICQ Legacy Client Setup (ICQ 98a / 99a / 99b)

This guide explains how to install and configure **ICQ 98a**, **ICQ 99a**, or
**ICQ 99b** for Open OSCAR Server using the legacy ICQ protocol (v3-v5 over
UDP).

> These clients use the legacy ICQ protocol, which is different from the OSCAR
> protocol used by ICQ 2000b and later. The server must have legacy ICQ support
> enabled (`ICQ_LEGACY_ENABLED=true`, which is the default). The protocol
> version is auto-detected from each client's packets.

## Protocol Versions

| Version | Clients | Status |
|---------|---------|--------|
| V5 | ICQ 99a, ICQ 99b | Supported (default) |
| V4 | ICQ 98a (some builds; later builds use V5) | Supported (default) |
| V3 | ICQ Groupware | Supported (default) |
| V2 | ICQ 1.111 Beta (1997, Win95/NT4 only), ICQ 1.111 Beta for Windows 3.11, open-source center client (early centericq/centerim) | Supported (default) |
| V1 | ICQ 1.02 Beta (1996) | Unsupported (logging only) |

V1 clients (ICQ 1.02 Beta) require Windows 95 or NT 4.0 and will not install on
later versions. V2 clients (ICQ 1.111 Beta, 1997) also require Windows 95/NT4
or Windows 3.11. The V2 protocol supports login, messaging, authorization,
presence, status changes, contact list, search, and profile updates. V2 clients
see advanced statuses (N/A, Occupied, DND) from later clients mapped to the
closest V2 equivalent (Away or DND).

## Download

Download ICQ 98a, 99a, or 99b from
[oldversion.com](https://www.oldversion.com/software/icq/) or another software
archive site. Third-party clients that use the legacy ICQ protocol (V3-V5)
should also be supported -- feel free to test and report.

## Installation

### Windows

1. **Run Installer**

   Run the ICQ installer and follow the prompts.

2. **Start Registration Wizard**

   After installation, the ICQ registration wizard will appear.

3. **Configure Server**

   Click the **For admin use** button at the bottom of the registration wizard.

   Enter the following:
   - **Server**: Your server's hostname or IP address (e.g. `127.0.0.1` for
     local testing, or your server's public IP/hostname).
   - **Port**: `4000` (the default legacy ICQ UDP port).

   Click OK to save the server settings.

4. **Complete Registration**

   Proceed through the registration wizard as normal. You can either register a
   new account or log in with an existing one, depending on your server
   configuration.

   > If `ICQ_LEGACY_AUTO_REGISTRATION=true` is set in your server config, the
   > client can create new accounts directly through the registration wizard.
   > Otherwise, create accounts via the management API first.

### Linux

You can run ICQ 98/99 under Linux via [WINE](https://www.winehq.org/).

1. **Install WINE**

   Install [WINE](https://wiki.winehq.org/Download) for your distribution.

2. **Run the Installer**

   ```shell
   wine icq99a.exe
   ```

3. **Configure Server**

   When the registration wizard appears, click **For admin use** and enter your
   server hostname and port `4000` as described in the Windows steps above.

4. **Complete Registration**

   Proceed through the wizard as normal.

## Server Configuration

The legacy ICQ server listens on UDP port 4000 by default. Key settings in
`config/settings.env`:

```
# Enable legacy ICQ protocol support
ICQ_LEGACY_ENABLED=true

# UDP listener address
ICQ_LEGACY_UDP_LISTENER=0.0.0.0:4000

# Supported protocol versions (V2, V3, V4, V5 are production-ready)
ICQ_LEGACY_VERSIONS=2,3,4,5

# Enable direct connections for following protocol versions for peer-to-peer
# communication (file transfer, direct chat). Will leak client IP address
# in presence notifications. Mixing direct connections between different ICQ
# versions can cause older clients to crash on peer-to-peer connection requests.
ICQ_LEGACY_DIRECT_CONNECTIONS=5
```

## Docker

If running via Docker, ensure UDP port 4000 is mapped in `docker-compose.yaml`:

```yaml
ports:
  - "4000:4000/udp"
```

This mapping is included in the default `docker-compose.yaml`.

## Troubleshooting

- **Client connects but nothing happens**: Verify the server shows
  `legacy ICQ server started` in the logs with the correct port and versions.
- **Connection timeout**: Check that UDP port 4000 is reachable from the client.
  Firewalls often block UDP traffic by default.
- **Registration fails**: Ensure `ICQ_LEGACY_AUTO_REGISTRATION=true` is set, or
  create the account via the management API before logging in.
- **File transfer / direct chat not working**: Enable direct connections for the
  client's protocol version: `ICQ_LEGACY_DIRECT_CONNECTIONS=5` (or `3,4,5`).
