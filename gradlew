name: Build PLSChat Android APK

# Run it from the GitHub "Actions" tab (Run workflow), or automatically when
# you push a version tag like v1.0. GitHub's runners have the Android SDK, so
# the signed APK is built for you in the cloud — no local tooling required.
on:
  workflow_dispatch:
  push:
    tags:
      - 'v*'

permissions:
  contents: write

jobs:
  build:
    runs-on: ubuntu-latest
    env:
      HAS_SIGNING: ${{ secrets.PLSCHAT_KEYSTORE_BASE64 != '' }}
    defaults:
      run:
        working-directory: app-android

    steps:
      - name: Checkout
        uses: actions/checkout@v4

      - name: Set up JDK 17
        uses: actions/setup-java@v4
        with:
          distribution: temurin
          java-version: '17'

      - name: Set up Android SDK
        uses: android-actions/setup-android@v3

      - name: Install SDK packages
        run: |
          sdkmanager "platform-tools" "platforms;android-34" "build-tools;34.0.0"

      - name: Decode signing keystore (if configured)
        if: ${{ env.HAS_SIGNING == 'true' }}
        env:
          KS_B64: ${{ secrets.PLSCHAT_KEYSTORE_BASE64 }}
        run: |
          echo "$KS_B64" | base64 -d > app/plschat-release.jks
          echo "Keystore written ($(wc -c < app/plschat-release.jks) bytes)"

      - name: Build release APK
        env:
          PLSCHAT_STORE_PASSWORD: ${{ secrets.PLSCHAT_STORE_PASSWORD }}
          PLSCHAT_KEY_ALIAS: ${{ secrets.PLSCHAT_KEY_ALIAS }}
          PLSCHAT_KEY_PASSWORD: ${{ secrets.PLSCHAT_KEY_PASSWORD }}
        run: |
          chmod +x gradlew
          ./gradlew --no-daemon assembleRelease

      - name: Collect APK
        run: |
          APK=$(find app/build/outputs/apk/release -name "*.apk" | head -n1)
          echo "Built: $APK"
          cp "$APK" "$GITHUB_WORKSPACE/PLSChat.apk"

      - name: Upload APK artifact
        uses: actions/upload-artifact@v4
        with:
          name: PLSChat-apk
          path: PLSChat.apk

      # Publish the APK straight to the website (served at https://plschat.net/PLSChat.apk)
      - name: Commit APK to site root
        run: |
          cd "$GITHUB_WORKSPACE"
          git config user.name  "github-actions[bot]"
          git config user.email "github-actions[bot]@users.noreply.github.com"
          git add PLSChat.apk
          if git diff --cached --quiet; then
            echo "APK unchanged, nothing to commit."
          else
            git commit -m "Publish PLSChat Android APK [skip ci]"
            git push
          fi

      # Also attach the APK to a GitHub Release when you push a version tag.
      - name: Publish GitHub Release
        if: startsWith(github.ref, 'refs/tags/v')
        uses: softprops/action-gh-release@v2
        with:
          files: PLSChat.apk
