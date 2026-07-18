# PLSChat Android app — build & release setup

This repo builds the PLSChat companion Android app **in the cloud** via GitHub
Actions. You don't need Android Studio or any local tooling — GitHub's runners
have the Android SDK, and the workflow generates the Gradle wrapper itself.

## What's in the repo

```
app-android/                     # the Android project
  build.gradle                   # top-level (AGP 8.5.2)
  settings.gradle
  gradle.properties
  gradlew / gradlew.bat          # wrapper scripts (the .jar is generated in CI)
  gradle/wrapper/gradle-wrapper.properties
  app/
    build.gradle                 # module: net.plschat.app, minSdk 26, targetSdk 34
    proguard-rules.pro
    src/main/AndroidManifest.xml
    src/main/java/net/plschat/app/MainActivity.java
    src/main/res/...             # strings, colors, theme, icons, network config
.github/workflows/android-build.yml
app.html                         # public download page (links to PLSChat.apk)
```

> **Note on `gradle-wrapper.jar`:** it is intentionally **not** committed (it's a
> binary and keeps the repo text-only). The workflow runs
> `gradle wrapper --gradle-version 8.7` on the runner to produce it before
> building, so nothing is missing. If you'd rather commit the jar, run
> `gradle wrapper --gradle-version 8.7` locally in `app-android/` once and commit
> the generated `gradle/wrapper/gradle-wrapper.jar`; the CI step is harmless
> either way.

## Build it

1. Go to the repo's **Actions** tab.
2. Select **Build PLSChat Android APK**.
3. Click **Run workflow**.

When it finishes, the APK is available three ways:

- as a workflow **artifact** (`PLSChat-apk`), and
- committed to the site root as **`PLSChat.apk`** (so `app.html`'s download
  button works, served at e.g. `https://plschat.net/PLSChat.apk`), and
- attached to a **GitHub Release** if you triggered the build by pushing a
  version tag (`git tag v1.0 && git push --tags`).

## Signing (recommended, optional)

Without signing secrets, the workflow still produces an installable APK signed
with the debug key. For a stable, upgradeable release identity, add these repo
**Secrets** (Settings → Secrets and variables → Actions):

| Secret | Meaning |
| --- | --- |
| `PLSCHAT_KEYSTORE_BASE64` | your `.jks` keystore, base64-encoded |
| `PLSCHAT_STORE_PASSWORD`  | keystore password |
| `PLSCHAT_KEY_ALIAS`       | key alias (defaults to `plschat`) |
| `PLSCHAT_KEY_PASSWORD`    | key password |

Create a keystore and encode it:

```bash
keytool -genkeypair -v -keystore plschat-release.jks \
  -alias plschat -keyalg RSA -keysize 2048 -validity 10000

base64 -w0 plschat-release.jks    # copy this into PLSCHAT_KEYSTORE_BASE64
# (on macOS: base64 -i plschat-release.jks | tr -d '\n')
```

The workflow decodes the keystore only when `PLSCHAT_KEYSTORE_BASE64` is set;
otherwise it silently falls back to the debug key. No secrets are stored in the
repo.

## The app in one paragraph

`MainActivity` is a single framework-only screen (no AndroidX/Material
dependency). It uses `ConnectivityManager` + `WifiNetworkSpecifier` to join a
`PLSChat-*` hotspot and **binds the app's process** to that internet-less
network, then shows the device's own web UI (`http://192.168.4.1/`) in a
`WebView`. `network_security_config.xml` permits cleartext only to that IP.
