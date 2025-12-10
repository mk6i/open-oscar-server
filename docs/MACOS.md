# Open OSCAR Server Quickstart for macOS (Intel and Apple Silicon)

This guide explains how to download, configure and run Open OSCAR Server on macOS (Intel and Apple Silicon).

1. **Download Open OSCAR Server**

   Grab the latest macOS release from the [Releases page](https://github.com/mk6i/open-oscar-server/releases) for your
   platform (Intel or Apple Silicon).

   Because the Open OSCAR Server binary has not been blessed by Apple, browsers such as Chrome may think it's a
   "suspicious" file and block the download, in which case you need to explicitly opt in to downloading the untrusted
   file.

    <p align="center">
      <img alt="screenshot of a chrome prompt showing a blocked download" src="https://github.com/mk6i/open-oscar-server/assets/2894330/90af40bd-262d-4e0f-a769-06943c7acd18">
    </p>

   > While the binaries are 100% safe, you can avoid the security concern by [building the application yourself](./BUILD.md).
   We do not provide signed binaries because of the undue cost and complexity.

   Once downloaded, extract the `.zip` archive, which contains the application and a configuration file `settings.env`.

2. **Open Terminal**

   Open a terminal and navigate to the extracted directory. This terminal will be used for the remaining steps.

   ```shell
   cd ~/Downloads/open_oscar_server.0.21.0.macos.intel_x86_64/
   ```

3. **Remove Quarantine**

   macOS will quarantine the Open OSCAR Server binary because it has not been blessed by Apple. To remove the quarantine
   flag from the binary, run following command in the same terminal,

   ```shell
   sudo xattr -d com.apple.quarantine ./open_oscar_server
   ```

   > While the binaries are 100% safe, you can avoid the security concern by [building the application yourself](./BUILD.md).
   We do not provide signed binaries because of the undue cost and complexity.

4. **Configure Server Address**

   Set the default listener in `OSCAR_ADVERTISED_LISTENERS_PLAIN` in `settings.env` to a hostname and port that the AIM
   clients can connect to. If you are running the AIM client and server on the same machine, you don't need to change
   the default value.

   The format is `[NAME]://[HOSTNAME]:[PORT]` where:
    - `LOCAL` is the listener name (can be any name you choose, as long as it matches the `OSCAR_LISTENERS` config)
    - `127.0.0.1` is the hostname clients connect to
    - `5190` is the port number clients connect to

   In order to connect AIM clients on your LAN (including VMs with bridged networking), you can find the appropriate IP
   address by running the following command in the terminal and use that IP instead of `127.0.0.1`:

   ```shell
   osascript -e "IPv4 address of (system info)"
   ```

5. **Start the Application**

   Run the following command to launch Open OSCAR Server:

   ```shell
   ./open_oscar_server
   ```

   Open OSCAR Server will run in the terminal, ready to accept AIM client connections.

6. **Test**

   To do a quick sanity check, start an AIM client, sign in to the server, and send yourself an instant message.
   Configure the AIM client to connect to the host and port from `OSCAR_ADVERTISED_LISTENERS_PLAIN` in `settings.env`. If using the default server setting, set host to `127.0.0.1` and port `5190`.

   See the [Client Configuration Guide](./CLIENT.md) for more detail on setting up the AIM client.

   By default, you can enter *any* screen name and password at the AIM sign-in screen to auto-create an account.

   > Account auto-creation is meant to be a convenience feature for local development. In a production deployment, you
   should set `DISABLE_AUTH=false` in `settings.env` to enforce account authentication. User accounts can be created via
   the [Management API](../README.md#-management-api).

7. **Additional Setup**

   For optional configuration steps that enhance your Open OSCAR Server experience, refer to
   the [Additional Setup Guide](./ADDITIONAL_SETUP.md).