# PLSChat over Bluetooth — SenseCAP T1000-E

The PLSChat Android app now has **two** ways to reach a device:

| Transport | Hardware | How it works |
|-----------|----------|--------------|
| **Wi-Fi** (original) | Heltec V4 / XIAO (ESP32) | The device serves its full web UI over its own hotspot at `192.168.4.1`. `MainActivity` binds the app's process to that Wi-Fi and loads the UI in a WebView. |
| **Bluetooth** (new) | SenseCAP T1000-E (nRF52840 + LR1110) | The tracker has **no Wi-Fi**. It runs the PLSChat tracker firmware, which exposes a Nordic UART (BLE) service and relays public-channel messages to/from the LoRa mesh. `BleActivity` connects to it and hosts a bundled chat UI (`assets/tracker.html`). |

Both live in the same app and the same APK. The Wi-Fi flow is unchanged and is
still the default screen; a link on that screen ("Using a SenseCAP tracker?
Connect over Bluetooth →") opens the Bluetooth flow.

## Why a tracker can't use the Wi-Fi flow

The Wi-Fi app is a WebView that loads a web page **served by the device**. The
T1000-E is a Nordic nRF52840 + LoRa part with no Wi-Fi radio, so it can't host
that page. Instead the phone talks to it directly over BLE and the chat UI is
bundled into the app.

## NUS line protocol

Both sides speak newline-delimited UTF-8 text over the Nordic UART Service
(`6E400001-…`; write `…0002`, notify `…0003`):

```
app -> device :  TX:<message>          send a public-channel message
                 WHO                   ask for this node's id
device -> app :  MSG:<8hexId>:<text>   an incoming public message
                 ME:<8hexId>           reply to WHO (our node id)
```

`BleActivity` reassembles notifications into lines, and the JS bridge
(`window.Android` / `window.__ble`) carries them to and from `tracker.html`.
Unknown line types are ignored on both ends, so newer firmware can add commands
without breaking this build.

## v1 scope — public channel only

This first version does exactly what the tracker firmware
(`firmware/plschat_t1000e_v0_1.ino`) supports today: **public-channel** messages,
byte-compatible with the Heltec fleet. The Contacts / Rooms tabs are visible in
the UI but disabled — they need the Curve25519 + contact-store port on the
firmware side before they can work over Bluetooth. When that lands, the app's
JSON-friendly bridge is where the richer commands get wired in.

## Not yet hardware-tested

The firmware's own header flags three things to confirm on a real T1000-E (RF
switch table, sync word, pin passthrough — see `firmware/plschat_t1000e_v0_1.ino`).
Until a tracker has been flashed and range-checked against a Heltec, treat the
end-to-end path as "built and logically verified" rather than "field-proven".

## Permissions

- **Android 12+**: `BLUETOOTH_SCAN` (with `neverForLocation`) and
  `BLUETOOTH_CONNECT`, requested at runtime. No location permission needed.
- **Android 8–11**: legacy `BLUETOOTH` / `BLUETOOTH_ADMIN`, plus
  `ACCESS_FINE_LOCATION` (required by the OS for BLE scanning on those versions).
