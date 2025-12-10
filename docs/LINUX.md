# Open OSCAR Server Quickstart for Linux (x86_64)

This guide explains how to download, configure and run Open OSCAR Server on Linux (x86_64).

1. **Download Open OSCAR Server**

   Grab the latest Linux release from the [releases page](https://github.com/mk6i/open-oscar-server/releases) and extract
   the archive. The extracted folder contains the application and a configuration file `settings.env`.

2. **Configure Server Address**

   Set the default listener in `OSCAR_ADVERTISED_LISTENERS_PLAIN` in `settings.env` to a hostname and port that the AIM
   clients can connect to. If you are running the AIM client and server on the same machine, you don't need to change
   the default value.

   The format is `[NAME]://[HOSTNAME]:[PORT]` where:
    - `LOCAL` is the listener name (can be any name you choose, as long as it matches the `OSCAR_LISTENERS` config)
    - `127.0.0.1` is the hostname clients connect to
    - `5190` is the port number clients connect to

   In order to connect AIM clients on your LAN (including VMs with bridged networking), you can find the appropriate IP
   address by running `ifconfig` from the terminal and use that IP instead of `127.0.0.1`.

3. **Start the Application**

   Run the following command to launch Open OSCAR Server:

   ```shell
   ./open_oscar_server
   ```

   Open OSCAR Server will run in the terminal, ready to accept AIM client connections.

4. **Configure AIM Clients**

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