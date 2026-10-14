# AIM for Android Client Setup

This guide explains how to run AIM for Android 1.10.9.1 in an Android 2.3.3 emulator and connect it to Open OSCAR
Server. The app talks to hardcoded AOL hostnames, so setup consists of redirecting those hostnames in the emulator and
installing your server's root CA certificate.

The examples in this guide assume your server's hostname is `ras.dev`, the hostname passed to `make docker-run`. If you
use a different hostname, substitute it wherever `ras.dev` appears.

<p align="center">
   <img width="350" alt="Android Screenshot" src="https://github.com/user-attachments/assets/359919aa-be84-4b3e-a3f9-9886686db47b" />
</p>

> [!NOTE]
> Open OSCAR Server is not affiliated with or endorsed by AOL or Yahoo. AIM and AIM for Android are trademarks of their
> respective owners. This project does not distribute the AIM for Android app; you are responsible for ensuring that
> obtaining and using it complies with the laws that apply to you.

## Prerequisites

1. **x86_64 Host**

   An Intel Mac, x86_64 Linux with KVM, or Windows with Windows Hypervisor Platform enabled On Windows, run the
   commands in PowerShell. Apple Silicon and other ARM hosts are not supported by the legacy Android version that runs
   the app.

   **Windows (PowerShell):**

   To enable Windows Hypervisor Platform, run the following in an Administrator PowerShell window, then reboot.

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
   ```

   After installing the emulator in step 3 of the setup procedure, `emulator -accel-check` should report
   `WHPX(...) is installed and usable`.

2. **JDK 17 or Later**

   The Android SDK tools require JDK 17 or later.

   **Linux:**

   On Ubuntu, run the following. On other distributions, install the equivalent package.

   ```shell
   sudo apt install openjdk-17-jdk-headless
   ```

   **macOS:**

   ```shell
   brew install --cask temurin@17
   ```

   **Windows (PowerShell):**

   ```powershell
   winget install EclipseAdoptium.Temurin.17.JDK
   ```

   Confirm that `java -version` reports version 17 or later. If your shell sets `JAVA_HOME`, point it at JDK 17 or
   later.

3. **SSL-Enabled Open OSCAR Server Instance**

   Configure and run an SSL-enabled Open OSCAR Server instance using the [Docker Setup Guide](./DOCKER.md). The Web API
   must be enabled (`WEBAPI_ENABLED=true`, the default).

## Setup Procedure

1. **Acquire the AIM APK**

   Download AIM 1.10.9.1 by searching for `AIM 1.10.9.1 APK`.

2. **Set Up the SDK Environment**

   **Linux:**

   ```shell
   export ANDROID_HOME="$HOME/Android/Sdk"
   export PATH="$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
   ```

   ```shell
   curl -O https://dl.google.com/android/repository/commandlinetools-linux-11479570_latest.zip
   mkdir -p "$ANDROID_HOME"
   unzip commandlinetools-linux-11479570_latest.zip -d "$ANDROID_HOME/cmdline-tools"
   mv "$ANDROID_HOME/cmdline-tools/cmdline-tools" "$ANDROID_HOME/cmdline-tools/latest"
   ```

   **macOS:**

   ```shell
   brew install --cask android-commandlinetools
   ```

   ```shell
   export ANDROID_HOME="$(brew --prefix)/share/android-commandlinetools"
   export PATH="$ANDROID_HOME/emulator:$ANDROID_HOME/platform-tools:$ANDROID_HOME/cmdline-tools/latest/bin:$PATH"
   ```

   **Windows (PowerShell):**

   ```powershell
   $env:ANDROID_HOME = "$env:LOCALAPPDATA\Android\Sdk"
   $env:Path = "$env:ANDROID_HOME\emulator;$env:ANDROID_HOME\platform-tools;$env:ANDROID_HOME\cmdline-tools\latest\bin;$env:Path"
   ```

   ```powershell
   curl.exe -O https://dl.google.com/android/repository/commandlinetools-win-11479570_latest.zip
   Expand-Archive commandlinetools-win-11479570_latest.zip "$env:ANDROID_HOME\cmdline-tools"
   Move-Item "$env:ANDROID_HOME\cmdline-tools\cmdline-tools" "$env:ANDROID_HOME\cmdline-tools\latest"
   ```

3. **Create the Emulator**

   ```shell
   sdkmanager "platform-tools" "emulator" "platforms;android-10" "system-images;android-10;default;x86"
   avdmanager create avd -n aim_api10 -k "system-images;android-10;default;x86" -d "3.2in HVGA slider (ADP1)"
   ```

   `sdkmanager` prompts you to accept each SDK license; enter `y` to continue. `avdmanager` may print
   `Could not load devices from ... devices.xml` errors. These are harmless.

   Android 2.3.3 (API 10) is the oldest x86 system image still available, and it was current when this version of AIM
   was released in 2011. The ADP1 device profile matches the small 320x480 screen the app was designed for.

4. **Start the Emulator**

   ```shell
   emulator -avd aim_api10 -writable-system -no-snapshot-save -gpu swiftshader_indirect -no-boot-anim
   ```

   Always start the emulator with `-writable-system`. Without it, the changes made in the next two steps are discarded.
   If the emulator fails to boot, replace `-gpu swiftshader_indirect` with `-gpu off`.

5. **Redirect the AOL Hostnames**

   In a second terminal, add the AOL hostnames to the emulator's hosts file. `10.0.2.2` is the emulator's address for
   the host machine. If the server runs on a different machine, use that machine's IP address instead.

   **macOS / Linux:**

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

   **Windows (PowerShell):**

   ```powershell
   adb root
   adb remount
   adb pull /system/etc/hosts .
   $entries = "`n10.0.2.2  api.oscar.aol.com`n10.0.2.2  api.screenname.aol.com`n10.0.2.2  login.oscar.aol.com`n10.0.2.2  my.screenname.aol.com`n"
   [IO.File]::AppendAllText("$PWD\hosts", $entries)
   adb push hosts /system/etc/hosts
   ```

   Alternatively, you can redirect these hostnames for your whole network with DNS poisoning: configure a local DNS
   server you control, such as dnsmasq or Pi-hole, to answer for them with your server's IP address. The emulator uses
   the host machine's DNS settings, so this works as long as the host uses that DNS server.

6. **Install the Root CA Certificate**

   On the host machine, download your server's root CA certificate from `http://ras.dev/certs/ca.crt`, or copy it from
   `certs/ca.crt` in your Open OSCAR Server directory. The download requires the host machine to resolve `ras.dev`.


   > On Windows, use `curl.exe` instead of `curl` in this step.

   ```shell
   curl -O http://ras.dev/certs/ca.crt
   ```

   Then run the following commands from the directory containing `ca.crt`.

   ```shell
   curl -O https://repo1.maven.org/maven2/org/bouncycastle/bcprov-jdk18on/1.78/bcprov-jdk18on-1.78.jar
   adb pull /system/etc/security/cacerts.bks .
   keytool "-J-Dorg.bouncycastle.bks.enable_v1=true" -importcert -v -trustcacerts -noprompt -alias openoscarca -file ca.crt -keystore cacerts.bks -storetype BKS-V1 -providerclass org.bouncycastle.jce.provider.BouncyCastleProvider -providerpath bcprov-jdk18on-1.78.jar -storepass changeit
   adb root
   adb remount
   adb push cacerts.bks /system/etc/security/cacerts.bks
   adb shell chmod 644 /system/etc/security/cacerts.bks
   adb reboot
   ```

7. **Install and Launch the Client**

   ```shell
   adb install -r </path/to/app.apk>
   adb shell am start -n com.aol.mobile.aim/com.aol.mobile.aim.ui.AimActivity
   ```

   Substitute `</path/to/app.apk>` with the path to the `.apk` file downloaded in step 1.

   Sign in with your Open OSCAR Server screen name and password.

## Troubleshooting

**`sdkmanager` or `avdmanager` reports that it requires JDK 17 or later**

Point `JAVA_HOME` at JDK 17 or later.

**The emulator exits with `x86 emulation currently requires hardware acceleration!`**

The host has no usable hypervisor. On Windows, enable Windows Hypervisor Platform as described in the prerequisites,
then confirm with `emulator -accel-check`. On Linux, confirm that KVM is available (`/dev/kvm` exists).

**The client can't connect**

Open `https://api.oscar.aol.com/` in the emulator's browser. If successful, you should see the following payload:

```json
{"response":{"statusCode":200,"statusText":"Ok","data":{}}}
```

If the page fails to load, the emulator can't reach the server: confirm the server is running, and check the hosts file
entries from step 5 and the certificate from step 6.
