# Open OSCAR Server Quickstart for Windows 10/11

This guide explains how to download, configure and run Open OSCAR Server on Windows 10/11.

1. **Download Open OSCAR Server**

   Download the latest Windows release from the [Releases page](https://github.com/mk6i/open-oscar-server/releases) and
   extract the `.zip` archive, which contains the application and a configuration file `settings.env`.

2. **Configure Server Address**

   Open `settings.env` (right-click, `edit in notepad`) and set the default listener in `OSCAR_ADVERTISED_LISTENERS_PLAIN` to
   a hostname and port that the AIM clients can connect
   to. If you are running the AIM client and server on the same machine, you don't need to change the default value.

   The format is `[NAME]://[HOSTNAME]:[PORT]` where:
    - `LOCAL` is the listener name (can be any name you choose, as long as it matches the `OSCAR_LISTENERS` config)
    - `127.0.0.1` is the hostname clients connect to
    - `5190` is the port number clients connect to

   In order to connect AIM clients on your LAN (including VMs with bridged networking), you can find the appropriate IP
   address by running `ipconfig` from the Command Prompt and use that IP instead of `127.0.0.1`.

3. **Start the Application**

   Launch `open_oscar_server.exe` to start Open OSCAR Server.

   Because Open OSCAR Server has not built up enough reputation with Microsoft, Windows will flag the application as a
   security risk the first time you run it. You'll be presented with a `Microsoft Defender SmartScreen` warning prompt
   that gives you the option to run the blocked application.

   To proceed, click `More Options`, then `Run anyway`.

    <p align="center">
      <img alt="screenshot of microsoft defender smartscreen prompt" src="https://github.com/mk6i/open-oscar-server/assets/2894330/9ab0966b-d5dd-4b70-ba16-483e5c458f89">
      <img alt="screenshot of microsoft defender smartscreen prompt" src="https://github.com/mk6i/open-oscar-server/assets/2894330/5d4106c6-0ce6-4d4f-9260-e9bbb777c770">
    </p>

   Click `Allow` if you get a Windows Defender Firewall alert.

    <p align="center">
      <img alt="screenshot of microsoft defender firewall alert" src="https://github.com/user-attachments/assets/9ec6cbc4-5445-43bd-a64e-512fd15f8f0b">
    </p>

   Open OSCAR Server will open in a terminal, ready to accept AIM client connections.

4. **Test**

   To do a quick sanity check, start an AIM client, sign in to the server, and send yourself an instant message.
   Configure the AIM client to connect to the host and port from `OSCAR_ADVERTISED_LISTENERS_PLAIN` in `settings.env`. If
   using the default server setting, set host to `127.0.0.1` and port `5190`.

   See the [Client Configuration Guide](./CLIENT.md) for more detail on setting up the AIM client.

   By default, you can enter *any* screen name and password at the AIM sign-in screen to auto-create an account.

   > Account auto-creation is meant to be a convenience feature for local development. In a production deployment, you
   should set `DISABLE_AUTH=false` in `settings.env` to enforce account authentication. User accounts can be created via
   the [Management API](../README.md#-management-api).

5. **Additional Setup**

   For optional configuration steps that enhance your Open OSCAR Server experience, refer to
   the [Additional Setup Guide](./ADDITIONAL_SETUP.md).