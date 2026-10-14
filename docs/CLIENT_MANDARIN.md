# Mandarin Client Setup

This guide explains how to build Mandarin 1.9.7, an open-source Android ICQ client, run it in an Android 5.1 emulator,
and connect it to Open OSCAR Server. The client talks to the server's Web API, so setup consists of pointing the app's
server URLs at your Open OSCAR Server instance, building it from source, and installing it in the emulator.

The SSL-enabled examples in this guide assume your server's hostname is `ras.dev`, the hostname passed to
`make docker-run`. If you use a different hostname, substitute it wherever `ras.dev` appears.

<p align="center">
   <img width="350" alt="Mandarin Screenshot" src="https://github.com/user-attachments/assets/7b53c7cf-dafc-4ec9-829f-27ddbe45afb5" />
</p>

## Prerequisites

1. **Compatible Host**

   An Intel or Apple Silicon Mac, x86_64 Linux with KVM, or Windows with Windows Hypervisor Platform enabled. On
   Windows, run the commands in PowerShell, not WSL.

   **Windows (PowerShell):**

   To enable Windows Hypervisor Platform, run the following in an Administrator PowerShell window, then reboot.

   ```powershell
   Enable-WindowsOptionalFeature -Online -FeatureName HypervisorPlatform
   ```

   After installing the emulator in step 2 of the setup procedure, `emulator -accel-check` should report
   `WHPX(...) is installed and usable`.

2. **JDK 17 or Later and JDK 8**

   The Android SDK tools require JDK 17 or later, and the app builds with JDK 8. Install both, for example from
   [Eclipse Temurin](https://adoptium.net/) or [Amazon Corretto](https://aws.amazon.com/corretto/), and keep JDK 17 or
   later as your default `JAVA_HOME`.

   **Linux:**

   On Ubuntu, run the following. On other distributions, install the equivalent packages.

   ```shell
   sudo apt install openjdk-17-jdk-headless openjdk-8-jdk-headless
   ```

   Confirm that `java -version` reports version 17. If it reports 1.8, run `sudo update-alternatives --config java`
   and select JDK 17.

   **macOS:**

   ```shell
   brew install --cask corretto@8 temurin@17
   ```

   Confirm that `java -version` reports version 17 or later. If your shell sets `JAVA_HOME`, point it at JDK 17 or
   later.

   **Windows (PowerShell):**

   ```powershell
   winget install Amazon.Corretto.8.JDK
   winget install EclipseAdoptium.Temurin.17.JDK
   ```

   The Corretto 8 installer makes JDK 8 the system default `JAVA_HOME`. Open a new PowerShell window after installing;
   step 1 of the setup procedure points `JAVA_HOME` back at JDK 17 or later for the current session.

3. **Git**

   **Linux:** `sudo apt install git`

   **macOS:** `xcode-select --install`

   **Windows (PowerShell):**

   ```powershell
   winget install Git.Git
   ```

4. **Open OSCAR Server Instance**

   Configure and run an Open OSCAR Server instance using one of the available guides.

    - For a simple **unencrypted** installation, follow the release setup guide for your operating system.
        - [Windows](./WINDOWS.md)
        - [Linux](./LINUX.md)
        - [macOS (Intel & Apple Silicon)](./MACOS.md)
    - For an advanced **SSL-enabled** installation, follow the [Docker Setup Guide](./DOCKER.md).

   The Web API must be enabled (`WEBAPI_ENABLED=true`, the default).

## Setup Procedure

1. **Set Up the SDK Environment**

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
   $env:JAVA_HOME = (Get-ChildItem "C:\Program Files\Eclipse Adoptium" -Directory -Filter "jdk-*" | Sort-Object Name -Descending | Select-Object -First 1).FullName
   ```

   ```powershell
   curl.exe -O https://dl.google.com/android/repository/commandlinetools-win-11479570_latest.zip
   Expand-Archive commandlinetools-win-11479570_latest.zip "$env:ANDROID_HOME\cmdline-tools"
   Move-Item "$env:ANDROID_HOME\cmdline-tools\cmdline-tools" "$env:ANDROID_HOME\cmdline-tools\latest"
   ```

2. **Create the Emulator**

   Choose the system image that matches your host: `arm64-v8a` on Apple Silicon and other ARM hosts, or `x86_64`
   everywhere else. Replace `<ABI>` below with your choice.

   ```shell
   sdkmanager "platform-tools" "emulator" "platforms;android-22" "platforms;android-27" "build-tools;27.0.3" "system-images;android-22;default;<ABI>"
   avdmanager create avd -n mandarin_api22 -k "system-images;android-22;default;<ABI>" -d pixel_5
   ```

   `sdkmanager` prompts you to accept each SDK license; enter `y` to continue. `avdmanager` may print
   `Could not load devices from ... devices.xml` errors. These are harmless.

3. **Clone the Source**

   ```shell
   git clone https://github.com/solkin/mandarin-android-legacy.git
   cd mandarin-android-legacy
   git checkout 1.9.7
   ```

4. **Fix the Build Repositories**

   In `build.gradle`, update both `repositories` blocks:

   ```diff
    buildscript {
        repositories {
   -        jcenter()
            google()
   +        mavenCentral()
        }
        ...
    }

    allprojects {
        repositories {
   -        jcenter()
            google()
   +        mavenCentral()
   +        maven { url 'https://jitpack.io' }
        }
    }
   ```

   In `app/build.gradle`, update the StickyHeaders dependency:

   ```diff
    dependencies {
        ...
        implementation 'se.emilsjolander:stickylistheaders:2.7.0' // TODO: remove
   -    implementation 'org.zakariya.stickyheaders:stickyheaders:0.7.6'
   +    implementation 'com.github.ShamylZakariya:StickyHeaders:v0.7.6'
        implementation 'com.github.machinarius:preferencefragment:0.1.1'
        ...
    }
   ```

5. **Configure Server URLs**

   Edit `app/src/main/java/com/tomclaw/mandarin/im/icq/WimConstants.java`, replacing the existing value of each
   constant in the table below. `{BASE}` is your server's base URL:

    - **Unencrypted:** `http://<server-ip>:8081/`, where `<server-ip>` is the LAN IP address or hostname of the
      machine running Open OSCAR Server, and `8081` is the default Web API port (`WEBAPI_LISTENERS`). Do not use
      `127.0.0.1`, which refers to the emulator itself.
    - **SSL-enabled:** `https://ras.dev/`, where `ras.dev` is the hostname you passed to `make docker-run`. The
      emulator must be able to resolve this hostname, either through DNS or its hosts file (step 8).

   <div align="center"><br>

   | Constant            | Value                     |
   |---------------------|---------------------------|
   | `CLIENT_LOGIN_URL`  | `{BASE}auth/clientLogin`  |
   | `START_SESSION_URL` | `{BASE}aim/startSession`  |
   | `RENEW_TOKEN_URL`   | `{BASE}auth/getInfo`      |

   </div>

   For example, an unencrypted server at `192.168.1.10:8081` gives `START_SESSION_URL` the value
   `http://192.168.1.10:8081/aim/startSession`.

6. **Build the APK**

   Run the following from the `mandarin-android-legacy` directory to build with JDK 8:

   **Linux:**

   ```shell
   JAVA_HOME=$(echo /usr/lib/jvm/java-8-openjdk-*) ./gradlew assembleDebug
   ```

   On distributions other than Ubuntu, replace the path with your JDK 8 install directory.

   **macOS:**

   ```shell
   JAVA_HOME=$(/usr/libexec/java_home -v 1.8) ./gradlew assembleDebug
   ```

   **Windows (PowerShell):**

   ```powershell
   $env:JAVA_HOME = (Get-ChildItem "C:\Program Files\Amazon Corretto" -Directory -Filter "jdk1.8*").FullName
   .\gradlew.bat assembleDebug
   ```

   The APK is written to `app/build/outputs/apk/debug/app-debug.apk`.

7. **Start the Emulator**

   ```shell
   emulator -avd mandarin_api22 -writable-system -no-snapshot-save -no-boot-anim
   ```

   For an SSL-enabled setup, always start the emulator with `-writable-system`. If the emulator fails to boot, add
   `-gpu swiftshader_indirect` or `-gpu off`.

8. **Redirect the Server Hostname (SSL only)**

   In a second terminal, map `ras.dev` to the host machine in the emulator's hosts file. If the server runs on a
   different machine, use that machine's IP address instead of `10.0.2.2`.

   **macOS / Linux:**

   ```shell
   adb root
   adb remount
   adb pull /system/etc/hosts .
   echo "10.0.2.2  ras.dev" >> hosts
   adb push hosts /system/etc/hosts
   ```

   **Windows (PowerShell):**

   ```powershell
   adb root
   adb remount
   adb pull /system/etc/hosts .
   [IO.File]::AppendAllText("$PWD\hosts", "`n10.0.2.2  ras.dev`n")
   adb push hosts /system/etc/hosts
   ```

9. **Install the Root CA Certificate (SSL only)**

   Download your server's root CA certificate from `http://ras.dev/certs/ca.crt`, or copy it from `certs/ca.crt` in
   your Open OSCAR Server directory.

   > On Windows, use `curl.exe` instead of `curl`.

   ```shell
   curl -O http://ras.dev/certs/ca.crt
   ```

   Run the following from the directory containing `ca.crt`. On Windows, `openssl` is included with
   [Git for Windows](https://gitforwindows.org/) under `C:\Program Files\Git\usr\bin`.

   **macOS / Linux:**

   ```shell
   HASH=$(openssl x509 -inform PEM -subject_hash_old -in ca.crt -noout)
   adb root
   adb remount
   adb push ca.crt "/system/etc/security/cacerts/$HASH.0"
   adb shell chmod 644 "/system/etc/security/cacerts/$HASH.0"
   adb reboot
   ```

   **Windows (PowerShell):**

   ```powershell
   $hash = openssl x509 -inform PEM -subject_hash_old -in ca.crt -noout
   adb root
   adb remount
   adb push ca.crt "/system/etc/security/cacerts/$hash.0"
   adb shell chmod 644 "/system/etc/security/cacerts/$hash.0"
   adb reboot
   ```

10. **Install and Launch the Client**

    ```shell
    adb install -r app/build/outputs/apk/debug/app-debug.apk
    adb shell am start -n com.tomclaw.mandarin/.main.MainActivity
    ```

    If you rebuild the app with a different base URL, run `adb uninstall com.tomclaw.mandarin` before installing it.
    Otherwise, the app keeps its session with the previous server.

    Tap **I already have login and password**, then sign in with your Open OSCAR Server UIN or screen name and
    password.

## Troubleshooting

**`sdkmanager` or `avdmanager` reports that it requires JDK 17 or later**

The error may also appear as `UnsupportedClassVersionError ... class file version 61.0`. Point `JAVA_HOME` at JDK 17 or
later. Only the build in step 6 uses JDK 8.

**The emulator exits with `x86 emulation currently requires hardware acceleration!`**

The host has no usable hypervisor. On Windows, enable Windows Hypervisor Platform as described in the prerequisites,
then confirm with `emulator -accel-check`. On Linux, confirm that KVM is available (`/dev/kvm` exists).

**The build fails before compiling**

If the build reports `Could not determine java version from '<version>'`, Gradle is running on a JDK other than JDK 8.
Confirm that JDK 8 is installed and that `"$JAVA_HOME/bin/java" -version` reports version 1.8 when run with the
`JAVA_HOME` value from step 6. On macOS, `/usr/libexec/java_home -v 1.8` must print a path; if it doesn't, install the
`corretto@8` cask.

**The client can't connect**

Open `https://ras.dev/` in the emulator's browser. If you're running an unencrypted setup or a different hostname,
adjust the URL to match the base URL you configured in step 5 (for example, `http://192.168.1.10:8081/`). If
successful, you should see the following payload:

```json
{"response":{"statusCode":200,"statusText":"Ok","data":{}}}
```

If the page fails to load, the emulator can't reach the server: check the URL, confirm the server is running, and for
an SSL-enabled setup, check the hosts file entry from step 8 and the certificate from step 9.
