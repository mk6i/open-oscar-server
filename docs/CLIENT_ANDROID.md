# AIM for Android Client Setup

This guide explains how to run the stock AIM for Android client (`com.aol.mobile.aim` 1.10.9.1, released April 2011)
against Open OSCAR Server, using an Android 2.3.3 emulator on Intel macOS.

Unlike the desktop AIM clients, this one has no server settings screen. It talks to hardcoded AOL hostnames, so getting
it connected means redirecting those hostnames to your machine and teaching the emulator to trust your server's
certificate.

## Why API 10, and why Intel

The APK declares `minSdkVersion=3` (Android 1.5) and `targetSdkVersion=4` (Android 1.6). It ships no native libraries,
and its manifest sets `supports-screens anyDensity="false"` with `largeScreens="false"` — it expects a small, mdpi
screen. API 10 (Android 2.3.3 Gingerbread) is the oldest system image Google still publishes for x86, and it was the
current release the week this APK was built, which makes it the closest thing to what the client was actually tested
against.

> **This guide requires an Intel Mac.** x86 system images below API 21 cannot run on Apple Silicon — the emulator exits
> with `Avd's CPU Architecture 'x86' is not supported by the QEMU2 emulator`. On Apple Silicon the oldest usable image is
> `system-images;android-21;default;arm64-v8a`, and the CA installation in step 7 is different there (Android 4.0+ has a
> user certificate store; Gingerbread does not).

## Prerequisites

- [Docker Desktop](https://docs.docker.com/get-started/get-docker/), for running the server (see [DOCKER.md](DOCKER.md))
- A JDK, for `keytool`
- The Android command line tools and platform tools

```shell
brew install --cask temurin@21
brew install android-commandlinetools android-platform-tools
```

You will also need the APK itself, which is archived on
[APKMirror](https://www.apkmirror.com/apk/aol-inc/aim/) among other places.

## 1. Set up the SDK environment

Homebrew does not put the SDK binaries on your `PATH`. Add them to your shell, or source them per session:

```shell
export ANDROID_HOME=/usr/local/share/android-commandlinetools
export PATH="$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
```

> On Apple Silicon the Homebrew prefix is `/opt/homebrew` instead of `/usr/local`.

Verify:

```shell
adb version
sdkmanager --version
```

## 2. Create the emulator

```shell
sdkmanager "system-images;android-10;default;x86" "platforms;android-10" emulator platform-tools

avdmanager create avd -n aim_api10 \
  -k "system-images;android-10;default;x86" \
  -d "3.2in HVGA slider (ADP1)"
```

`platform-tools` has to be installed here even though `brew install android-platform-tools` already put `adb` on your
`PATH`. The emulator decides whether a directory is a valid SDK root by looking for a `platform-tools` *subdirectory*
inside it, and Homebrew installs to `/usr/local/bin` instead. Without the sdkmanager copy the emulator refuses to start:

```
WARNING | platform-tools subdirectory is missing under /usr/local/share/android-commandlinetools
FATAL   | Cannot find AVD system path. Please define ANDROID_SDK_ROOT
```

`avdmanager` prints `Error: Could not load devices from .../devices.xml` while creating the AVD. That one is harmless —
the device profile is still applied. Confirm with `grep hw.lcd ~/.android/avd/aim_api10.avd/config.ini`, which should
report 320x480 at density 160.

The `3.2in HVGA slider (ADP1)` profile is 320x480 at mdpi, which is exactly the screen the manifest asks for. On a
larger or denser profile the app is bitmap-stretched into screen compatibility mode, which is a rendering path that was
never tested in 2011.

## 3. Boot with a writable system partition

```shell
emulator -avd aim_api10 -writable-system -no-snapshot-save -gpu swiftshader_indirect -no-boot-anim
```

`-writable-system` is required. Steps 6 and 7 modify `/system`, and without this flag the emulator boots a pristine
`system.img` on every launch and those edits are silently discarded.

`-gpu swiftshader_indirect` is needed because a 2011 system image predates the emulator's default graphics backend. If
the emulator still fails to boot, try `-gpu off`.

Confirm it came up:

```shell
adb wait-for-device
adb devices
```

## 4. Start the server

Follow [DOCKER.md](DOCKER.md) for the full walkthrough. The short version:

```shell
make docker-images
make docker-cert OSCAR_HOST=ras.dev
make docker-run OSCAR_HOST=ras.dev
```

No extra certificate configuration is needed for this client. The certificate `make docker-cert` generates already
carries a `subjectAltName` covering `api.oscar.aol.com`, `api.screenname.aol.com`, `login.oscar.aol.com` and
`my.screenname.aol.com`. Only the first two and `my.screenname.aol.com` actually appear in the APK — `login.oscar.aol.com`
is not in the dex at all, and is covered here and in step 6 only because it costs nothing. The matching root certificate
lands at `certs/ca.crt`, and you install it on the emulator in step 7.

For reference, this is what the client calls:

| Purpose                                     | URL                               | Protocol                        |
|---------------------------------------------|-----------------------------------|---------------------------------|
| `auth/clientLogin`                          | `https://api.screenname.aol.com/` | HTTPS — requires the root CA    |
| `aim/startSession`, `aim/fetchEvents`, etc. | `http://api.oscar.aol.com/`       | plain HTTP                      |

Setting `DISABLE_AUTH=true` will auto-create accounts on first sign-in, which saves a trip through the management API
while you are getting set up. Set it in whichever settings file you actually launch with — `config/ssl/settings.env` for
the SSL/nginx setup this guide uses, `config/settings.env` for the plain one.

## 5. Register the client's API key

The Web API requires a developer key in the `k` query parameter. This client has its key hardcoded to
`ao1BsrrRGV1M-xS4`, and `cmd/webapi_keygen` only mints random keys, so the row has to go in by hand:

```shell
sqlite3 oscar.sqlite <<'SQL'
INSERT INTO web_api_keys
  (dev_id, dev_key, app_name, created_at, is_active, rate_limit, allowed_origins, capabilities)
VALUES
  ('dev_aim_android', 'ao1BsrrRGV1M-xS4', 'AIM for Android', strftime('%s','now'), 1, 600, '[]', '[]');
SQL
```

Requests that carry an `a=` auth token are accepted even when the key is unknown, but the endpoints that authenticate on
`k` alone return `403 invalid API key` without this row.

## 6. Redirect the AOL hostnames

The emulator reaches your Mac's loopback address at `10.0.2.2`. Point the hardcoded hostnames there.

Android 2.3 has no `sed -i`, so pull the file, edit it on the host, and push it back:

```shell
adb root
adb remount

adb pull /system/etc/hosts .
cat >> hosts <<'EOF'
10.0.2.2  api.oscar.aol.com
10.0.2.2  api.screenname.aol.com
10.0.2.2  login.oscar.aol.com
10.0.2.2  my.screenname.aol.com
EOF
adb push hosts /system/etc/hosts
```

Verify:

```shell
adb shell ping -c1 api.oscar.aol.com
```

## 7. Install the root CA

Android 4.0 and later have a user certificate store and a *Settings → Security → Install certificate* flow. **Gingerbread
has neither.** Its entire trust store is one BouncyCastle keystore at `/system/etc/security/cacerts.bks`, and the only
way to add a CA is to merge it into that file.

There is no way around this: the client installs no custom `TrustManager`, so an untrusted CA means `clientLogin` fails
TLS validation and sign-in hangs on a spinner forever.

```shell
curl -O https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78/bcprov-jdk18on-1.78.jar

adb pull /system/etc/security/cacerts.bks .

keytool -J-Dorg.bouncycastle.bks.enable_v1=true \
  -importcert -v -trustcacerts -alias openoscarca \
  -file certs/ca.crt \
  -keystore cacerts.bks \
  -storetype BKS-V1 \
  -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
  -providerpath bcprov-jdk18on-1.78.jar \
  -storepass changeit
```

Three things to watch for:

- `-J-Dorg.bouncycastle.bks.enable_v1=true` is not optional on modern BouncyCastle. Since 1.71 the provider registers
  the `BKS-V1` keystore type only when that system property is set — `BC$Mappings.configure` gates the
  `addAlgorithm("KeyStore.BKS-V1", ...)` call behind `Properties.isOverrideSet("org.bouncycastle.bks.enable_v1")`.
  Without it the import fails immediately with `java.security.KeyStoreException: BKS-V1 not found`. The `-J` prefix is
  how `keytool` forwards a flag to its own JVM.
- `-storetype BKS-V1` is not optional either. BouncyCastle 1.47 and later default to writing BKS **v2**, which
  Gingerbread cannot parse.
- `changeit` is the stock password on the shipped `cacerts.bks`.

Verify the result before pushing it. The entry count should go up by exactly one, and the first four bytes of the file
should still read `00000001` — that is the BKS format version, and a `00000002` there means you have a v2 keystore that
Gingerbread will not load:

```shell
keytool -J-Dorg.bouncycastle.bks.enable_v1=true -list \
  -keystore cacerts.bks -storetype BKS-V1 \
  -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider \
  -providerpath bcprov-jdk18on-1.78.jar \
  -storepass changeit | grep -c trustedCertEntry     # 127 before, 128 after

xxd -l 4 cacerts.bks                                 # 00000000: 0000 0001
```

Once it checks out, push it back:

```shell
adb root
adb remount
adb push cacerts.bks /system/etc/security/cacerts.bks
adb shell chmod 644 /system/etc/security/cacerts.bks
```

Then restart the emulator so the new trust store is read at boot. Do not use `adb reboot` — on this image it shuts the
emulator down instead of restarting it, leaving the process dead and `adb devices` empty. Kill it and boot it again:

```shell
adb emu kill
emulator -avd aim_api10 -writable-system -no-snapshot -gpu swiftshader_indirect -no-boot-anim
```

Nothing is lost in the process. `-writable-system` keeps your `/system` edits in `system.img.qcow2` inside the AVD
directory, so both the hosts file and the trust store survive a cold boot as long as every launch passes the flag.

You can sanity check the certificate chain from the host before going back to the emulator:

```shell
curl --cacert certs/ca.crt https://api.screenname.aol.com/auth/clientLogin
```

## 8. Install the client

```shell
adb install -r "com.aol.mobile.aim_1.10.9.1-138_minAPI3(nodpi).apk"
```

Launch it from the app drawer, or:

```shell
adb shell am start -n com.aol.mobile.aim/com.aol.mobile.aim.ui.AimActivity
```

Sign in with any screen name and password. With `DISABLE_AUTH=true` the account is created on first use.

## 9. Verify

Watch the client:

```shell
adb logcat | grep -i aim
```

Watch the server. A successful sign-in produces `/aim/startSession` followed by a steady stream of `/aim/fetchEvents`
long-polls. The nginx access log records the negotiated TLS parameters per request:

```
ssl=TLSv1/RC4-MD5
```

`TLSv1` is expected here — Gingerbread predates TLS 1.2 — and the client negotiates an equally period-appropriate
cipher; `RC4-MD5` and `AES128-SHA` are both normal. The `ras-nginx:1.28.0-openssl-1.0.2u` image this project pins
exists precisely to keep those protocols and ciphers available, so no configuration change is needed.

Only `auth/clientLogin` goes over TLS. Everything after it is plain HTTP on port 80 and logs as `ssl=-/-`, so a
successful run looks roughly like this:

```
"POST /auth/clientLogin HTTP/1.1" 200 ssl=TLSv1/RC4-MD5
"GET /aim/startSession?a=...&k=ao1BsrrRGV1M-xS4... HTTP/1.1" 200 ssl=-/-
"GET /aim/fetchEvents?aimsid=...&seqNum=0&timeout=180000 HTTP/1.1" 200 ssl=-/-
```

`fetchEvents` long-polls with `timeout=180000`, so once the client settles an idle session produces one request every
few minutes rather than a fast stream. A rising `seqNum` is the thing to watch.

## Troubleshooting

**`Avd's CPU Architecture 'x86' is not supported by the QEMU2 emulator`**

You are on Apple Silicon. x86 images below API 21 will not run there; use
`system-images;android-21;default;arm64-v8a` or newer instead.

**The hosts file or certificate reverts after a reboot**

The emulator was started without `-writable-system`. Every launch needs the flag, not just the one where you made the
edits.

**`keytool error: java.security.KeyStoreException: BKS-V1 not found`**

The `-J-Dorg.bouncycastle.bks.enable_v1=true` flag is missing. See step 7.

**`Cannot find AVD system path. Please define ANDROID_SDK_ROOT`**

`platform-tools` is not installed inside the SDK root. Run `sdkmanager "platform-tools"` — the Homebrew formula alone
does not satisfy this. See step 2.

**Sign-in shows a spinner that never resolves**

The root CA is not trusted. Confirm the store you pushed is v1 and contains your CA, using the two verification commands
at the end of step 7. A v2 keystore loads as empty on Gingerbread and every TLS connection fails.

**`adb devices` is empty after `adb reboot`**

`adb reboot` shuts this image down rather than restarting it. Relaunch the emulator; see step 7.

**The emulator will not boot**

A 2011 system image against a current emulator release is a long reach. Try `-gpu off`, and if that fails, install an
older `emulator` package through `sdkmanager`.

**`adb shell input keyevent 82` opens the menu once, then stops working**

Dismiss the menu with the back key before sending the menu key again:

```shell
adb shell input keyevent 4
```

**`Error: Unknown command: tap`**

API 10's `input` only implements `text` and `keyevent`; `tap` arrives in a later release. Drive the UI with the D-pad
instead — `19` up, `20` down, `21` left, `22` right, `23` select, `4` back. The sign-in screen is reachable that way:
`19` to the username field, type, `20` to the password field, type, then `20` `20` `23` to press **Sign In**.

**`adb shell screencap` is not found**

Also missing on API 10. Reading `/dev/graphics/fb0` is not a workaround either — under QEMU2 it returns all zeros
whatever `-gpu` mode you boot with. Take screenshots through the emulator console, which writes a PNG to a directory on
the host:

```shell
mkdir -p "$PWD/shots"
adb emu screenrecord screenshot "$PWD/shots"
```

The path must be absolute. The emulator resolves a relative one against its own working directory, not your shell's, and
still answers `OK` — so a relative path looks like it worked while writing nothing where you expected it.
