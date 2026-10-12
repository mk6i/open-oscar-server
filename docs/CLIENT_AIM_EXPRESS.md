# AIM Express Client Setup

This guide explains how to run AIM Express, AOL's Flash-based web AIM client, and connect it to Open OSCAR Server.
Open OSCAR Server's nginx container serves the client's web assets, which you download from the Internet Archive.
The client sends its API requests to hardcoded AOL hostnames, so setup also consists of redirecting those hostnames to
your server and trusting your server's root CA certificate in the browser.

The examples in this guide assume your server's hostname is `ras.dev`, the hostname passed to `make docker-run`. If you
use a different hostname, substitute it wherever `ras.dev` appears.

<p align="center">
   <img width="551" alt="AIM Express Screenshot" src="https://github.com/user-attachments/assets/2a0b3c96-4597-4995-a832-f0342338466a" />
</p>

> [!NOTE]
> Open OSCAR Server is not affiliated with or endorsed by AOL or Yahoo. AIM and AIM Express are trademarks of their
> respective owners. This project does not distribute the AIM Express client; you are responsible for ensuring that
> obtaining and using it complies with the laws that apply to you.

## Prerequisites

1. **Flash-Enabled Web Browser**

   Any browser that can run the Adobe Flash Player plugin works. On Windows XP, for example,
   [Mypal](https://www.mypal-browser.org/) supports Flash.

   The [Ruffle](https://ruffle.rs/) Flash emulator does not yet run the client completely.

2. **SSL-Enabled Open OSCAR Server Instance**

   Configure and run an SSL-enabled Open OSCAR Server instance using the [Docker Setup Guide](./DOCKER.md). The Web API
   must be enabled (`WEBAPI_ENABLED=true`, the default).

## Setup Procedure

1. **Download the Web Assets**

   Download the following files from the [Wayback Machine](https://web.archive.org/). Make sure to download the
   original files rather than the archive's viewer pages, especially for the `.swf` files.

   | CDN URL                                                                                                              |
   |----------------------------------------------------------------------------------------------------------------------|
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/AC_OETags.js`                                     |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/ConversationAssets.swf`                           |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/OnlinePanel.swf`                                  |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/WidgetMain.html`                                  |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/WidgetMain.swf`                                   |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/_uac/adpage.html`                                 |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/babybunny.png`               |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/default_buddy_icon.png`      |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/default_imserv_icon.png`     |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/default_login_user_icon.png` |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/aim-express/progress_animation.swf`      |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/check.png`              |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/facebook_h.png`         |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/facebook_n.png`         |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/ls_h.png`               |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/ls_n.png`               |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/plus.png`               |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/twitter_h.png`          |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/twitter_n.png`          |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/youtube_h.png`          |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/chicklets/youtube_n.png`          |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/all.gif`              |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/facebook.gif`         |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/lifestream.gif`       |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/location.gif`         |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/myspace.gif`          |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/photo.gif`            |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/status.gif`           |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/twitter.gif`          |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/filterTypes/video.gif`            |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/help/aim_or_fb.html`              |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/common/serviceicons/runningman.png`      |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/loadable/emoticons/GromitEmoticons.swf`           |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/norris.txt`                                       |
   | `http://o.aolcdn.com/aim/gromit/aim_express/gm/100820.5475.1.en-us/portal.php`                                       |

2. **Place the Web Assets**

   Save each file under `clients/express/` in your Open OSCAR Server directory, keeping the part of its path after
   `100820.5475.1.en-us/`. nginx serves this directory at `http://ras.dev/client/express/`.

   The finished file tree should look like this:

   ```
   clients/express/
   ├── AC_OETags.js
   ├── ConversationAssets.swf
   ├── OnlinePanel.swf
   ├── WidgetMain.html
   ├── WidgetMain.swf
   ├── _uac
   │   └── adpage.html
   ├── loadable
   │   ├── aim-express
   │   │   ├── babybunny.png
   │   │   ├── default_buddy_icon.png
   │   │   ├── default_imserv_icon.png
   │   │   ├── default_login_user_icon.png
   │   │   └── progress_animation.swf
   │   ├── common
   │   │   ├── chicklets
   │   │   │   ├── check.png
   │   │   │   ├── facebook_h.png
   │   │   │   ├── facebook_n.png
   │   │   │   ├── ls_h.png
   │   │   │   ├── ls_n.png
   │   │   │   ├── plus.png
   │   │   │   ├── twitter_h.png
   │   │   │   ├── twitter_n.png
   │   │   │   ├── youtube_h.png
   │   │   │   └── youtube_n.png
   │   │   ├── filterTypes
   │   │   │   ├── all.gif
   │   │   │   ├── facebook.gif
   │   │   │   ├── lifestream.gif
   │   │   │   ├── location.gif
   │   │   │   ├── myspace.gif
   │   │   │   ├── photo.gif
   │   │   │   ├── status.gif
   │   │   │   ├── twitter.gif
   │   │   │   └── video.gif
   │   │   ├── help
   │   │   │   └── aim_or_fb.html
   │   │   └── serviceicons
   │   │       └── runningman.png
   │   └── emoticons
   │       └── GromitEmoticons.swf
   ├── norris.txt
   └── portal.php
   ```

3. **Redirect the Hostnames**

   On the machine running the browser, add the following entries to the hosts file. Replace `127.0.0.1` with the
   server's IP address if the server runs on a different machine.

   ```
   127.0.0.1  ras.dev
   127.0.0.1  api.oscar.aol.com
   127.0.0.1  api.screenname.aol.com
   127.0.0.1  login.oscar.aol.com
   127.0.0.1  my.screenname.aol.com
   ```

   The hosts file is `/etc/hosts` on macOS and Linux, and `C:\Windows\System32\drivers\etc\hosts` on Windows. Editing
   it requires administrator privileges. Skip the `ras.dev` entry if that hostname already resolves through DNS.

   Alternatively, you can redirect these hostnames for your whole network with DNS poisoning: configure a local DNS
   server you control, such as dnsmasq or Pi-hole, to answer for them with your server's IP address.

4. **Trust the Root CA Certificate**

   Open `http://ras.dev/certs/ca.crt` in the browser and trust the certificate to identify websites when prompted.
   Firefox-based browsers such as Mypal keep their own certificate store. Other browsers use the operating system's
   store, so on those, import `ca.crt` into the OS's trusted root certificates instead.

5. **Launch the Client**

   Open `http://ras.dev/client/express/WidgetMain.html` in the browser and sign in with your Open OSCAR Server screen
   name and password.

## Troubleshooting

**The client can't connect**

Open `https://api.screenname.aol.com/` in the same browser. If successful, you should see the following payload:

```json
{"response":{"statusCode":200,"statusText":"Ok","data":{}}}
```

If the page fails to load, the browser can't reach the server: confirm the server is running and check the hosts file
entries from step 3. If the browser shows a certificate warning, repeat step 4.

**The client page is blank or shows a Flash install prompt**

Confirm that the Flash plugin is installed and enabled for the site, and that the files in `clients/express/` match the
tree in step 2. Each `.swf` file should start with the bytes `CWS` or `FWS`. A file that starts with `<!DOCTYPE` or
`<html>` is a Wayback Machine viewer page rather than the original file; download the original file again.
