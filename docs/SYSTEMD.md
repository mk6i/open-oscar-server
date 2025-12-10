# Configuring Open OSCAR Server With systemd

This document details the configuration of Open OSCAR Server to run as an unprivileged user with `systemd` managing it as
a production service.

1. **Download Open OSCAR Server**

   Grab the latest Linux release from the [releases page](https://github.com/mk6i/open-oscar-server/releases)

2. **Create the ras user and group**

   Run the following commands:

   ```shell
   sudo useradd ras
   sudo mkdir -p /opt/ras
   ```

3. **Extract the archive**

   Extract the archive using the usual `tar` invocation, and move `open_oscar_server` into `/opt/ras`

4. **Set Ownership and Permissions**

   ```shell
   sudo chown -R ras:ras /opt/ras
   sudo chmod -R o-rx /opt/ras
   ```

5. **Copy the systemd service**

   Place the `ras.service` file in `/etc/systemd/system`

6. **Reload systemd**

   ```shell
   sudo systemctl daemon-reload
   ```

7. **Enable and start the service**

   ```shell
   sudo systemctl enable --now ras.service
   ```

8. **Make sure the service is running**

   ```shell
   sudo systemctl status ras.service
   sudo journalctl -xeu ras.service
   ```

Note that the `systemd` service defines the configuration for Open OSCAR Server directly, bypassing the `settings.env`
config. Customizations may be performed in `/etc/systemd/system/ras.service`.
