# ICQ Client Setup

This guide explains how to install and configure ICQ clients for Open
OSCAR Server.

Open OSCAR supports a majority of ICQ clients released over the years, including
the UDP-based Mirabilis versions from the late 1990s and the OSCAR-based releases
that followed. Setup differs by era: pre-OSCAR clients (98/99) use the legacy UDP
protocol, while ICQ 2000x and later use the OSCAR protocol.

- [ICQ 98a, 99a, 99b (pre-OSCAR)](#icq-98a-99a-99b-pre-oscar)
- [ICQ 2000b](#icq-2000b)
- [ICQ 2001 & 2002](#icq-2001--2002)
- [ICQ 2003, 4 & 5](#icq-2003-4--5)

## ICQ 98a, 99a, 99b (pre-OSCAR)

This guide explains how to install and configure **ICQ 98a**, **ICQ 99a**, or
**ICQ 99b** for Open OSCAR Server using the legacy ICQ protocol (v3-v5 over
UDP).

> These clients use the legacy ICQ protocol, which is different from the OSCAR
> protocol used by ICQ 2000b and later. The server must have legacy ICQ support
> enabled (`ICQ_LEGACY_ENABLED=true`, which is the default).

### Protocol Versions

| Version | Clients                                                                                                       | Status                                                     |
|---------|---------------------------------------------------------------------------------------------------------------|------------------------------------------------------------|
| V5      | ICQ 99a, ICQ 99b                                                                                              | Supported (default)                                        |
| V4      | ICQ 98a (some builds; later builds use V5)                                                                    | Supported (default)                                        |
| V3      | ICQ Groupware                                                                                                 | Supported (default)                                        |
| V2      | ICQ 1.111 Beta (1997, Win95/NT4 only), ICQ 1.111 Beta for Windows 3.11, open-source Centericq/CenterIM client | Supported (default)                                        |
| V1      | ICQ 1.02 Beta (1996)                                                                                          | Experimental (enable with `ICQ_LEGACY_VERSIONS=1,2,3,4,5`) |

V1 clients (ICQ 1.02 Beta) require Windows 95 or NT 4.0 and will not install on
later versions. V2 clients (ICQ 1.111 Beta, 1997) also require Windows 95/NT4
or Windows 3.11. The V2 protocol supports login, messaging, authorization,
presence, status changes, contact list, search, and profile updates. V2 clients
see advanced statuses (N/A, Occupied, DND) from later clients mapped to the
closest V2 equivalent (Away or DND).

### Download

Download ICQ 98a, 99a, or 99b from
[oldversion.com](https://www.oldversion.com/software/icq/) or another software
archive site. Third-party clients that use the legacy ICQ protocol (V3-V5)
should also be supported — feel free to test and report.

### Installation

#### Windows

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
   > Otherwise, create accounts via the [Management API](../api.yml) first.

#### Linux

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

   Proceed through the registration wizard as normal. You can either register a
   new account or log in with an existing one, depending on your server
   configuration.

   > If `ICQ_LEGACY_AUTO_REGISTRATION=true` is set in your server config, the
   > client can create new accounts directly through the registration wizard.
   > Otherwise, create accounts via the [Management API](../api.yml) first.

### Server Configuration

The legacy ICQ server listens on UDP port 4000 by default. Key settings in
`config/settings.env`:

```dotenv
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

### Docker

If running via Docker, ensure UDP port 4000 is mapped in `docker-compose.yaml`:

```yaml
ports:
  - "4000:4000/udp"
```

This mapping is included in the default `docker-compose.yaml`.

### Troubleshooting

- **Client connects but nothing happens**: Verify the server shows
  `legacy ICQ server started` in the logs with the correct port and versions.
- **Connection timeout**: Check that UDP port 4000 is reachable from the client.
  Firewalls often block UDP traffic by default.
- **Registration fails**: Ensure `ICQ_LEGACY_AUTO_REGISTRATION=true` is set, or
  create the account via the [Management API](../api.yml) before logging in.
- **File transfer / direct chat not working**: Enable direct connections for the
  client's protocol version: `ICQ_LEGACY_DIRECT_CONNECTIONS=5` (or `3,4,5`).

## ICQ 2000b

This guide explains how to install and configure **ICQ 2000b** for Open OSCAR
Server.

> ICQ 2000b has a quirk that must be addressed post-installation via the
> Windows Registry for proper operation. Do not set the server hostname through
> the registration wizard — see [Post-install Configuration](#post-install-configuration).

These clients store your contact list locally on the client. ICQ 2000b runs on
native Windows and under [WINE](https://www.winehq.org/) on Linux and macOS
(via [Sikarugir](https://github.com/Sikarugir-App/Sikarugir)).

Installation guides are available for the following operating systems:

- [Windows](#windows-1)
- [Linux](#linux-1)
- [macOS (Intel & Apple Silicon)](#macos-intel--apple-silicon)

### Installation

#### Windows

1. **Download ICQ**

   Download ICQ 2000b from [archive.org](https://archive.org/details/icq2000b_202206).

2. **Run Installer**

   Run the ICQ installer.

3. **Close the Registration Window**

   Once installation is complete, you'll be greeted by an ICQ registration window.
   *Do not complete the registration wizard.* Close the window and move on to
   the [post-installation steps](#post-install-configuration).

    <p align="center">
       <img width="400" alt="screenshot of ICQ registration window" src="https://github.com/user-attachments/assets/b5684b93-02b0-4314-adfa-16ea9826cf69">
    </p>

#### Linux

You can run ICQ 2000b under Linux via [WINE](https://www.winehq.org/).

1. **Download ICQ**

   Download ICQ 2000b from [archive.org](https://archive.org/details/icq2000b_202206).

2. **Install WINE**

   Run and install [WINE](https://wiki.winehq.org/Download).

3. **Run the Installer**

   Start the ICQ installer under WINE from a terminal:
   ```shell
   wine icq2000b.exe
   ```

4. **Close the Registration Window**

   Once installation is complete, you'll be greeted by an ICQ registration window.
   *Do not complete the registration wizard.* Close the window and move on to
   the [post-installation steps](#post-install-configuration).

    <p align="center">
        <img width="400" alt="screenshot of ICQ registration window" src="https://github.com/user-attachments/assets/d9820dc6-c29b-4ff6-9dfe-5a6bcd9effc5">
    </p>

#### macOS (Intel & Apple Silicon)

Windows ICQ 2000b can run on modern macOS (including the Apple Silicon platform) without a VM
using [Sikarugir](https://github.com/Sikarugir-App/Sikarugir), a wrapper for WINE.

1. **Install Sikarugir**

   Install Sikarugir via homebrew:

   ```shell
   brew install --cask Sikarugir-App/sikarugir/sikarugir
   /usr/sbin/softwareupdate --install-rosetta --agree-to-license # apple silicon only
   ```

2. **Create a Blank Application Wrapper**

   Launch `Sikarugir Creator`. Install the latest engine and create a new blank
   wrapper for installing ICQ.

   Generating the wrapper might take 1-2 minutes, and the application might not
   respond during this time. Once complete, click `View wrapper in Finder`.

   <p align="center">
      <img width="516" height="600" alt="screenshot of wrapper generator window" src="https://github.com/user-attachments/assets/578e9a35-e97e-4c14-bde8-8913b86551a7">
   </p>

3. **Install ICQ into the Application Wrapper**

   Launch the wrapper from the Finder window. Select `Install Software`.

   <p align="center">
      <img width="797" height="485" alt="screenshot of wrapper launcher" src="https://github.com/user-attachments/assets/6c9a2bbb-b28a-4437-ba4a-a8f866e58dd0">
   </p>

   Select `Choose Setup Executable` and open the ICQ installer executable.

   <p align="center">
      <img width="715" height="464" alt="screenshot of choosing executable" src="https://github.com/user-attachments/assets/8d2c8fb5-87cf-4f0a-b44c-3d437a779257">
   </p>

4. **Run the Installer**

   Complete the ICQ installation wizard.

5. **Close the Registration Window**

   Once installation is complete, you'll be greeted by an ICQ registration window.
   *Do not complete the registration wizard.* Close the window and move on to
   the [post-installation steps](#post-install-configuration).

    <p align="center">
       <img width="400" alt="screenshot of ICQ registration window" src="https://github.com/user-attachments/assets/b5684b93-02b0-4314-adfa-16ea9826cf69">
    </p>

### Post-install Configuration

In this step, we'll replace ICQ's default server hostname with your Open OSCAR
Server's hostname in the Windows Registry.

> Do not attempt to set the ICQ hostname via the registration wizard. If you do
> this, a bug will surface that prevents the client from "remembering" settings
> such as saved passwords and OSCAR hostname.

1. **Open Registry Editor**

    - Windows
        - Open the Run dialog <kbd>⊞ Win</kbd> + <kbd>`R`</kbd>.
        - Enter `regedit` and click `OK`.
    - Wine (Linux)
        - Open a terminal.
        - Run `wine regedit` in a terminal.
    - Sikarugir (macOS)
        - Open Finder and go to `~/Applications/Sikarugir/`.
        - Right-click your ICQ wrapper (e.g. `icq2000b.app`) and select **Show Package Contents**.
        - Open `Contents` → `Configure.app`.
        - Click `Tools` → `Registry Editor (regedit)`.

2. **Open Default ICQ Settings**

   Navigate to `HKEY_CURRENT_USER\Software\Mirabilis\ICQ\DefaultPrefs`.
   <p align="center">
      <img width="500" alt="screenshot of regedit" src="https://github.com/user-attachments/assets/02b20e3a-769c-4c69-bbf5-395684d8f30f">
   </p>

3. **Configure OSCAR Host**

    - Double-click the `Default Server Host` registry entry.
    - Set `Value data` to the hostname from `OSCAR_ADVERTISED_LISTENERS_PLAIN` found in Open OSCAR Server
      configuration `config/settings.env`. For example, if `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`,
      use `127.0.0.1`.
    - Click OK.

   <p align="center">
      <img width="325" alt="screenshot editing Default Server Host in regedit" src="https://github.com/user-attachments/assets/ebcf66fa-1841-41f7-986a-90b24dd0a94d">
   </p>

4. **Configure Server Port (uncommon)**

   Only change this value if your server does not listen on the default OSCAR
   ports.

    - Double-click the `Default Server Port` registry entry.
    - Tick the `Decimal` radio button.
    - Set `Value data` to the port number from `OSCAR_ADVERTISED_LISTENERS_PLAIN` found in Open OSCAR Server
      configuration
      `config/settings.env`. For example, if `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`, use `5190`.
    - Click OK.

   <p align="center">
      <img width="325" alt="screenshot editing Default Server Port in regedit" src="https://github.com/user-attachments/assets/11a3efff-40f1-4f1d-b88a-9c78fddb9c3d">
   </p>

5. **Exit Registry Editor**

   Client configuration is complete. Close the Registry Editor.

### First Time Login

Start ICQ and complete the first-time registration wizard. Start by selecting `Existing User`.

> Do not try to create a new user in the registration wizard. To create a new user in Open OSCAR Server, follow account
> creation steps in
> the [server quickstart guides](https://github.com/mk6i/open-oscar-server?tab=readme-ov-file#-how-to-run).

   <p align="center">
      <img width="400" alt="screenshot of ICQ registration wizard" src="https://github.com/user-attachments/assets/48c666a8-04c8-4b48-a86a-fc52e8a9af41">
   </p>

Enter ICQ user credentials. If `DISABLE_AUTH=true` in your server config (the
default in generated `config/settings.env`), you can enter any UIN and password.
For production, create accounts first and set `DISABLE_AUTH=false`. Click next
on the remaining screens until the wizard is finished.

<p align="center">
   <img width="400" alt="screenshot of ICQ registration wizard" src="https://github.com/user-attachments/assets/7520db7c-0512-42d1-88f3-e3f8f9d5eaec">
</p>

You should now be able to connect to Open OSCAR Server using ICQ 2000b.

## ICQ 2001 & 2002

This guide explains how to install and configure **ICQ 2001** and **ICQ 2002**
for Open OSCAR Server.

> Unlike ICQ 2000b, these clients store your contact list on the server rather
> than locally on the client. They also do not run reliably under WINE — use
> native Windows.

> Create accounts via
> the [server quickstart guides](https://github.com/mk6i/open-oscar-server?tab=readme-ov-file#-how-to-run)
> before signing in, unless `DISABLE_AUTH=true` in your server config.

1. **Download and install ICQ**

    - [ICQ 2001b](https://www.oldversion.com/software/icq/icq-2001b/)
    - [ICQ 2002a](https://www.oldversion.com/software/icq/icq-2002a/)

2. **Start as an existing user**

   You'll be greeted with a setup wizard.

   <p align="center">
      <img width="514" alt="ICQ 2002 setup wizard — existing user" src="https://github.com/user-attachments/assets/bc3493e7-d4e0-4ad8-acb7-63f0f7fa511a" />
   </p>

3. **Enter ICQ number and password**

   Enter your UIN and password.

   <p align="center">
      <img width="513" alt="ICQ 2002 setup wizard — UIN and password" src="https://github.com/user-attachments/assets/4e8749b7-9be6-4cd8-bb6d-44cd894691e0">
   </p>

4. **Wait for connection timeout**

   The setup wizard will attempt to connect to the default ICQ servers that no longer exist. Wait for the wizard to time
   out, then click `Connection Settings`.

   <p align="center">
      <img width="513" alt="ICQ 2002 setup wizard — connection timeout" src="https://github.com/user-attachments/assets/033b6688-ec7b-4e2a-ae77-56c07ded5e2f">
   </p>

5. **Enter Open OSCAR Server hostname and port**

   Set the hostname and port from `OSCAR_ADVERTISED_LISTENERS_PLAIN` in
   `config/settings.env`. For example, if
   `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`, set host to
   `127.0.0.1` and port to `5190`.

   <p align="center">
      <img width="514" alt="ICQ connection settings dialog" src="https://github.com/user-attachments/assets/0580d0c7-bdc2-4850-a305-3cf3e8955308">
   </p>

6. **Continue setup**

   Click through the remaining wizard screens until setup is complete.

   <p align="center">
      <img width="513" alt="ICQ 2002 setup wizard — final screen" src="https://github.com/user-attachments/assets/17d0bcb4-9782-4d13-aa87-1ad62323b974">
   </p>

You should now be able to connect to Open OSCAR Server using ICQ 2001 or 2002.

## ICQ 2003, 4 & 5

This guide explains how to install and configure **ICQ 2003**, **ICQ 4**, and **ICQ 5** for Open OSCAR Server.

> These clients store your contact list on the server
> rather than locally on the client. They also do not run reliably under WINE —
> use native Windows.

> Create accounts via
> the [server quickstart guides](https://github.com/mk6i/open-oscar-server?tab=readme-ov-file#-how-to-run)
> before signing in, unless `DISABLE_AUTH=true` in your server config.

1. **Download and install ICQ**

    - [ICQ 2003b](https://www.oldversion.com/software/icq/icq-2003b/)
    - [ICQ 4 Lite Edition](https://archive.org/details/tucows_283618_ICQ_4_Lite_Edition_with_Xtraz) (other ICQ 4 builds
      should work similarly)
    - [ICQ 5.1](https://www.oldversion.com/software/icq/icq-5-1/)

2. **Launch ICQ**

   At the login screen, click `Setup`.

   <p align="center">
      <img width="223" alt="ICQ 5 login screen with Setup button" src="https://github.com/user-attachments/assets/f1161ad3-d64f-4045-bfe5-79f418bb90ce">
   </p>

3. **Enter Open OSCAR Server hostname and port**

   Set the hostname and port from `OSCAR_ADVERTISED_LISTENERS_PLAIN` in
   `config/settings.env`. For example, if
   `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`, set host to
   `127.0.0.1` and port to `5190`.

   <p align="center">
      <img width="449" alt="ICQ server connection settings" src="https://github.com/user-attachments/assets/dc21c401-3dcd-4ee8-a586-ee620ffe7022">
   </p>

4. **Login with ICQ credentials**

   Sign in with your UIN and password. If login fails, verify the account exists
   on the server and that the hostname and port match
   `OSCAR_ADVERTISED_LISTENERS_PLAIN`.

You should now be able to connect to Open OSCAR Server using ICQ 2003, 4, or 5.