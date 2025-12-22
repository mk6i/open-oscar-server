# ICQ Client Setup

This guide explains how to install and configure **ICQ 2000b** for Open OSCAR Server.

> ICQ 2000b is the only version of ICQ currently supported by RAS.

Installation guides are available for the following operating systems:

* [Windows](#windows)
* [Linux](#linux)
* [macOS (Intel & Apple Silicon)](#macos-intel--apple-silicon)

## Installation

### Windows

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

### Linux

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

### macOS (Intel & Apple Silicon)

Windows ICQ 2000b can run on modern macOS (including the Apple Silicon platform) without a VM
using [WineskinServer](https://github.com/Gcenx/WineskinServer), a wrapper for WINE.

1. **Install WineskinServer**

   Install WineskinServer via homebrew:

   ```shell
   brew install --cask --no-quarantine gcenx/wine/wineskin
   ```

2. **Create a Blank Application Wrapper**

   Launch `Wineskin Winery`. Install the latest engine and create a new blank
   wrapper for installing ICQ.

   Generating the wrapper might take 1-2 minutes, and the application might not
   respond during this time. Once complete, click `View wrapper in Finder`.

   <p align="center">
      <img width="325" alt="screenshot of wineskin server" src="https://github.com/user-attachments/assets/8d2ed477-f41c-4f00-90c2-d24c468b4aae">
   </p>

3. **Install ICQ into the Application Wrapper**

   Launch the wrapper from the Finder window. Select `Install Software`.

   <p align="center">
      <img width="325" alt="screenshot of wineskin server" src="https://github.com/user-attachments/assets/a2c0882c-230f-4034-9670-6f309ec1f628">
   </p>

   Select `Choose Setup Executable` and open the ICQ installer executable.

   <p align="center">
      <img width="325" alt="screenshot of wineskin server" src="https://github.com/user-attachments/assets/cf6aa78b-6bc0-4cfe-b750-bf2c763acdfb">
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

## Post-install Configuration

In this step, we'll replace ICQ's default server hostname with your Open OSCAR
Server's hostname in the Windows Registry.

> Do not attempt to set the ICQ hostname via the registration Window. If you do
> this, a bug will surface that prevents the client from "remembering" settings
> such as saved passwords and OSCAR hostname.

1. **Open Registry Editor**

    - Windows
        - Open the Run dialog <kbd>⊞ Win</kbd> + <kbd>`R`</kbd>.
        - Enter `regedit` and click `OK`.
    - Wine (Linux)
        - Open a terminal.
        - Run `wine regedit` in a terminal.
    - WineskinServer (macOS)
        - Open a terminal.
        - Run the following command, substituting `icq2000b.app` with the file name of your wrapper:
          ```shell
          ~/Applications/Wineskin/icq2000b.app/Contents/Wineskin.app/Contents/Resources/regedit
          ```

2. **Open Default ICQ Settings**

   Navigate to `HKEY_CURRENT_USER\Software\Mirabilis\ICQ\DefaultPrefs`.
   <p align="center">
      <img width="500" alt="screenshot of regedit" src="https://github.com/user-attachments/assets/02b20e3a-769c-4c69-bbf5-395684d8f30f">
   </p>

3. **Configure OSCAR Host**

    - Double-click the `Default Server Host` registry entry.
    - Set `Value data` to the hostname from `OSCAR_ADVERTISED_LISTENERS_PLAIN` found in Open OSCAR Server
      configuration `config/settings.env`. For example, if `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`, use
      `127.0.0.1`.
    - Click OK.

   <p align="center">
      <img width="325" alt="screenshot editing Default Server Host in regedit" src="https://github.com/user-attachments/assets/ebcf66fa-1841-41f7-986a-90b24dd0a94d">
   </p>

4. **Configure Server Port (uncommon)**

   Only change this value if your server does not listen on the default OSCAR
   ports.

    - Double-click the `Default Server Port` registry entry.
    - Tick the `Decimal` radio button.
    - Set `Value data` to the port number from `OSCAR_ADVERTISED_LISTENERS_PLAIN` found in Open OSCAR Server configuration
      `config/settings.env`. For example, if `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`, use `5190`.
    - Click OK.

   <p align="center">
      <img width="325" alt="screenshot editing Default Server Port in regedit" src="https://github.com/user-attachments/assets/11a3efff-40f1-4f1d-b88a-9c78fddb9c3d">
   </p>

5. **Exit Registry Editor**

   Client configuration is complete. Close the Registry Editor.

## First Time Login

Start ICQ and complete the first-time registration wizard. Start by selecting `Existing User`.

> Do not try to create a new user in the registration wizard. To create a new user in Open OSCAR Server, follow account
> creation steps in
> the [server quickstart guides](https://github.com/mk6i/open-oscar-server?tab=readme-ov-file#-how-to-run).

   <p align="center">
      <img width="400" alt="screenshot of ICQ registration wizard" src="https://github.com/user-attachments/assets/48c666a8-04c8-4b48-a86a-fc52e8a9af41">
   </p>

Enter ICQ user credentials. If you're running RAS with the default settings,
you can enter *any* UIN and password. Click next on the remaining screens until
the wizard is finished.

<p align="center">
   <img width="400" alt="screenshot of ICQ registration wizard" src="https://github.com/user-attachments/assets/7520db7c-0512-42d1-88f3-e3f8f9d5eaec">
</p>

You should now be able to connect to Open OSCAR Server using ICQ 2000b.