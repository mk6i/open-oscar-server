# AIM for iOS Client Setup

This guide explains how to connect the AIM for iOS client (v5.1.3) to Open OSCAR Server. The client talks to the
server's Web API, so setup consists of pointing the app's server URLs at your Open OSCAR Server instance and installing
the modified app on your device.

<p align="center">
   <img width="320" alt="AIM for iOS Screenshot" src="https://github.com/user-attachments/assets/8b410e0e-060f-4626-bda9-e210f4a6548a" />
</p>

## Prerequisites

1. **Compatible iOS Device**

   AIM v5.1.3 is a 32-bit app, so it requires a device running iOS 5 through 10. iOS 11 and later do not run 32-bit
   apps.

2. **Ability to Sideload Apps**

   Your device must be jailbroken, with a package such as AppSync Unified installed so that it can run a modified,
   unsigned app. You also need to know how to modify an IPA file and install it onto your device.

3. **Open OSCAR Server Instance**

   Configure and run an Open OSCAR Server instance using one of the available guides.

    - For a simple **unencrypted** installation, follow the release setup guide for your operating system.
        - [Windows](./WINDOWS.md)
        - [Linux](./LINUX.md)
        - [macOS (Intel & Apple Silicon)](./MACOS.md)
    - For an advanced **SSL-enabled** installation, follow the [Docker Setup Guide](./DOCKER.md).

   The Web API must be enabled (`WEBAPI_ENABLED=true`, the default), and your device must be able to reach the server
   over the network.

## Setup Procedure

1. **Acquire the AIM IPA**

   Download AIM v5.1.3 from [archive.org](https://archive.org) by searching for `AOL Instant Messenger iOS`.

2. **Configure Server URLs**

   Modify the following production parameters in the IPA's `aim_servers.plist` file, replacing `{BASE}` with your
   server's base URL:

    - **Unencrypted:** `http://<server-ip>:8081/`, where `<server-ip>` is the LAN IP address or hostname of the
      machine running Open OSCAR Server, and `8081` is the default Web API port (`WEBAPI_LISTENERS`). Do not use
      `127.0.0.1`, which refers to the device itself.
    - **SSL-enabled:** `https://<OSCAR_HOST>/`, where `<OSCAR_HOST>` is the hostname you passed to
      `make docker-run` (e.g., `ras.dev`). The device must be able to resolve this hostname, either through DNS or its
      hosts file.

   <div align="center"><br>

   | Param                      | Value                                     |
   |----------------------------|-------------------------------------------|
   | `api_base_url`             | `{BASE}`                                  |
   | `api_secure_base_url`      | `{BASE}`                                  |
   | `auth_base_url`            | `{BASE}`                                  |
   | `sns_auth_url`             | `{BASE}_cqr/login/login.psp`              |
   | `lifestream_settings_url`  | `{BASE}lifestream/settings`               |
   | `lifestream_photo_api_url` | `{BASE}lifestream/`                       |
   | `registration_api_url`     | `{BASE}rsp-websvc-3.0/reg/`               |
   | `services_settings_url`    | `{BASE}.settings/mobile/accounts`         |
   | `social_notification_url`  | `{BASE}.settings/mobile/notifications`    |

   </div>

   For example, an unencrypted server at `192.168.1.10:8081` gives `sns_auth_url` the value
   `http://192.168.1.10:8081/_cqr/login/login.psp`.

3. **Install the IPA**

   Install the modified IPA onto your device.

4. **Install the Root CA Certificate (SSL only)**

   If you're running an SSL-enabled setup, the device must trust your server's root CA certificate.

   In Safari on the device, open `http://<OSCAR_HOST>/certs/ca.crt` and install the profile when prompted.

   <p align="center">
      <img width="320" alt="iOS Certificate Installation Screenshot" src="https://github.com/user-attachments/assets/b62aeb01-4d2a-4262-a602-d772f26b94b5" />
   </p>

   On iOS 10.3 and later, you must also enable full trust for the certificate under **Settings → General → About → Certificate
   Trust Settings**.

5. **Sign In**

   Open the AIM app and sign in!

## Troubleshooting

**The client can't connect**

Open `{BASE}` in Safari on the device. If successful, you should see the following payload:

```json
{"response":{"statusCode":200,"statusText":"Ok","data":{}}}
```

If the page fails to load, the device can't reach the server: check the URL, confirm the server is running, and make
sure the device and server are on the same network (guest Wi-Fi networks often block traffic between devices).
