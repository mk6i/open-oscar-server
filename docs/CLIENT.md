# Windows AIM 5.x Client Setup

This guide explains how to install and configure Windows AIM 5.x clients for Open OSCAR Server.

AIM 5.x is recommended if you want to experience the last version of AIM with the "classic" early-2000s feel.

## Installation

### Linux / FreeBSD

Windows AIM versions 5.0-5.1.3036 run perfectly well on [Wine](https://www.winehq.org/). Here's how to set up AIM
5.1.3036.

1. [Install Wine](https://wiki.winehq.org/Download)
2. Download the AIM installer from [archive.org](https://archive.org/details/aim513036)
3. Run the installer from the terminal:
   ```shell
   wine aim513036.exe
   ```

### macOS (Intel & Apple Silicon)

Windows AIM can run on modern macOS without a VM, including the Apple Silicon platform!

Get started with the [AIM for macOS project](https://github.com/mk6i/aim-for-macos).

### Windows 10/11

1. Download AIM 5.9.6089 (available on [oldversion.com](http://www.oldversion.com/windows/aol-instant-messenger/)).
2. Install AIM and exit out of the application post-installation.
3. Open **Task Manager** and kill the **AOL Instant Messenger (32 bit)** process to make sure the application is
   actually terminated.
4. Open **File Explorer** and navigate to `C:\Program Files (x86)\AIM`.
5. Delete `aimapi.dll`.
6. Set [Windows XP compatibility mode](https://support.microsoft.com/en-us/windows/make-older-apps-or-programs-compatible-with-windows-783d6dd7-b439-bdb0-0490-54eea0f45938)
on `aim.exe`.

7. Launch AIM.

## Configuration

Once installed, configure AIM to connect to Open OSCAR Server.

1. At the sign-on screen, click `Setup`.
   <p>
      <img width="319" alt="screenshot of AIM sign-on screen" src="https://github.com/mk6i/mkdb/assets/2894330/9e0e743e-e41d-4c45-9e82-d97d7d4325f3">
   </p>
2. Under the `Sign On/Off` category, click `Connection`.
   <p>
      <img width="662" alt="screenshot of AIM preferences window" src="https://github.com/mk6i/mkdb/assets/2894330/c7cfcaa4-8132-4b57-b5c9-7643c99cbda2">
   </p>
3. Configure the server host and port fields according to the `OSCAR_ADVERTISED_LISTENERS_PLAIN` configuration found in
   `config/settings.env`. For example, if `OSCAR_ADVERTISED_LISTENERS_PLAIN=LOCAL://127.0.0.1:5190`, set `Host` to
   `127.0.0.1` and `Port` to `5190`.
   <p>
      <img width="618" alt="screenshot of AIM host dialog" src="https://github.com/mk6i/mkdb/assets/2894330/da17c457-a773-4b82-b4ba-cb81f9a2e085">
   </p>
4. Click OK and sign in to AIM!
