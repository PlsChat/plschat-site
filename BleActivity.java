package net.plschat.app;

import android.Manifest;
import android.app.Activity;
import android.bluetooth.BluetoothAdapter;
import android.bluetooth.BluetoothDevice;
import android.bluetooth.BluetoothGatt;
import android.bluetooth.BluetoothGattCallback;
import android.bluetooth.BluetoothGattCharacteristic;
import android.bluetooth.BluetoothGattDescriptor;
import android.bluetooth.BluetoothGattService;
import android.bluetooth.BluetoothManager;
import android.bluetooth.le.BluetoothLeScanner;
import android.bluetooth.le.ScanCallback;
import android.bluetooth.le.ScanFilter;
import android.bluetooth.le.ScanResult;
import android.bluetooth.le.ScanSettings;
import android.content.Intent;
import android.content.pm.PackageManager;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.ParcelUuid;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.JavascriptInterface;
import android.webkit.WebChromeClient;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;

import org.json.JSONObject;

import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;

/**
 * PLSChat — SenseCAP T1000-E (Bluetooth) companion screen.
 *
 * The T1000-E is a Nordic nRF52840 + LoRa tracker. It has NO Wi-Fi, so the
 * Wi-Fi/WebView flow in {@link MainActivity} can't reach it. Instead it runs the
 * PLSChat tracker firmware (plschat_t1000e_v0_1.ino), which exposes a Nordic
 * UART Service (NUS) over BLE and bridges public-channel PLSChat messages to and
 * from the LoRa mesh.
 *
 * This activity is the app-side half of that bridge:
 *   - scans for / connects to the tracker's NUS,
 *   - reassembles newline-delimited lines from the device,
 *   - hosts a bundled chat UI (assets/tracker.html) in a WebView, and
 *   - exposes a tiny JS bridge so the UI can send/receive over BLE.
 *
 * NUS line protocol spoken by the firmware (both directions are UTF-8 text,
 * one command per '\n'-terminated line):
 *   app -> device :  "TX:<message>"   send a public-channel message
 *                    "WHO"            ask for this node's id
 *   device -> app :  "MSG:<8hexId>:<text>"   an incoming public message
 *                    "ME:<8hexId>"           reply to WHO (our node id)
 *
 * v1 scope: PUBLIC CHANNEL ONLY, matching the firmware's confirmed-working base.
 * Contacts / rooms / private (encrypted) messages need the nRF Curve25519 port
 * on the firmware side before they can be surfaced here.
 */
public class BleActivity extends Activity {

    // ---- Nordic UART Service UUIDs (as advertised by the tracker firmware) --
    private static final UUID NUS_SERVICE =
            UUID.fromString("6E400001-B5A3-F393-E0A9-E50E24DCCA9E");
    private static final UUID NUS_RX_WRITE =   // phone -> device (we write here)
            UUID.fromString("6E400002-B5A3-F393-E0A9-E50E24DCCA9E");
    private static final UUID NUS_TX_NOTIFY =  // device -> phone (we get notifies)
            UUID.fromString("6E400003-B5A3-F393-E0A9-E50E24DCCA9E");
    private static final UUID CCCD =
            UUID.fromString("00002902-0000-1000-8000-00805F9B34FB");

    private static final String NAME_PREFIX = "PLSChat-T1000";
    private static final long SCAN_TIMEOUT_MS = 15000L;
    private static final int REQ_PERMS = 101;
    private static final int REQ_ENABLE_BT = 102;

    // ------------------------------------------------------------- BLE state
    private BluetoothAdapter adapter;
    private BluetoothLeScanner scanner;
    private BluetoothGatt gatt;
    private BluetoothGattCharacteristic rxWrite;   // we write commands here
    private ScanCallback scanCallback;
    private boolean scanning = false;
    private boolean ready = false;                 // notifications enabled -> usable
    private int mtu = 20;                          // usable payload = mtu-3; 23 default
    private String deviceName = "";

    // GATT allows only one outstanding operation; serialise them.
    private final ArrayDeque<Runnable> gattQueue = new ArrayDeque<>();
    private boolean gattBusy = false;

    // Reassembly buffer for '\n'-delimited lines coming from the device.
    private final StringBuilder rxLineBuf = new StringBuilder();

    // ------------------------------------------------------------- UI state
    private FrameLayout root;
    private WebView web;
    private LinearLayout panel, topBar;
    private TextView status;
    private ProgressBar spinner;
    private Button connectBtn;
    private boolean webReady = false;

    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);

        BluetoothManager bm = (BluetoothManager) getSystemService(BLUETOOTH_SERVICE);
        adapter = (bm != null) ? bm.getAdapter() : null;

        root = new FrameLayout(this);
        root.setBackgroundColor(0xFF0a0c1f);

        buildWebView();
        buildTopBar();
        buildPanel();

        FrameLayout.LayoutParams webLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT);
        webLp.topMargin = dp(46);
        root.addView(web, webLp);
        FrameLayout.LayoutParams tbLp = new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(46));
        root.addView(topBar, tbLp);
        root.addView(panel, new FrameLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.MATCH_PARENT));

        web.setVisibility(View.GONE);
        topBar.setVisibility(View.GONE);
        setContentView(root);
    }

    // ---------------------------------------------------------------- WebView
    private void buildWebView() {
        web = new WebView(this);
        web.setBackgroundColor(0xFF0a0c1f);
        WebSettings s = web.getSettings();
        s.setJavaScriptEnabled(true);
        s.setDomStorageEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        web.addJavascriptInterface(new Bridge(), "Android");
        web.setWebViewClient(new WebViewClient() {
            @Override
            public void onPageFinished(WebView v, String url) {
                webReady = true;
                // Push the current connection state into the freshly-loaded UI.
                pushState();
            }
        });
        web.setWebChromeClient(new WebChromeClient());
    }

    // ----------------------------------------------------------------- Top bar
    private void buildTopBar() {
        topBar = new LinearLayout(this);
        topBar.setOrientation(LinearLayout.HORIZONTAL);
        topBar.setBackgroundColor(0xF012121f);
        topBar.setGravity(Gravity.CENTER_VERTICAL);
        topBar.setPadding(dp(14), 0, dp(8), 0);

        TextView title = new TextView(this);
        title.setText("PLSChat · Tracker");
        title.setTextColor(0xFFe4e4e7);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(title.getTypeface(), Typeface.BOLD);
        topBar.addView(title, new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f));

        Button reconnect = flatButton("Reconnect");
        reconnect.setOnClickListener(v -> showPanel(null));
        topBar.addView(reconnect);
    }

    // ------------------------------------------------------------- Connect UI
    private void buildPanel() {
        panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        panel.setGravity(Gravity.CENTER_HORIZONTAL);
        panel.setBackgroundColor(0xFF0a0c1f);
        panel.setPadding(dp(28), dp(48), dp(28), dp(28));

        ImageView logo = new ImageView(this);
        logo.setImageResource(R.drawable.ic_logo);
        LinearLayout.LayoutParams logoLp = new LinearLayout.LayoutParams(dp(88), dp(88));
        logoLp.bottomMargin = dp(12);
        panel.addView(logo, logoLp);

        TextView h = new TextView(this);
        h.setText("SenseCAP Tracker");
        h.setTextColor(0xFFffffff);
        h.setTextSize(TypedValue.COMPLEX_UNIT_SP, 26);
        h.setTypeface(h.getTypeface(), Typeface.BOLD);
        h.setGravity(Gravity.CENTER);
        panel.addView(h);

        TextView sub = new TextView(this);
        sub.setText("Connect to a SenseCAP T1000-E running PLSChat firmware over "
                + "Bluetooth. Public-channel messages are relayed to and from the "
                + "LoRa mesh.");
        sub.setTextColor(0xFF9ca3af);
        sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subLp.topMargin = dp(6);
        subLp.bottomMargin = dp(24);
        panel.addView(sub, subLp);

        connectBtn = primaryButton("Connect to tracker");
        connectBtn.setOnClickListener(v -> startConnectFlow());
        LinearLayout.LayoutParams cbLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        panel.addView(connectBtn, cbLp);

        Button wifi = secondaryButton("Use a Wi-Fi device instead");
        wifi.setOnClickListener(v -> finish());   // back to MainActivity (Wi-Fi)
        LinearLayout.LayoutParams wLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        wLp.topMargin = dp(10);
        panel.addView(wifi, wLp);

        spinner = new ProgressBar(this);
        spinner.setVisibility(View.GONE);
        LinearLayout.LayoutParams spLp = new LinearLayout.LayoutParams(dp(36), dp(36));
        spLp.topMargin = dp(16);
        panel.addView(spinner, spLp);

        status = new TextView(this);
        status.setTextColor(0xFFfca5a5);
        status.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        status.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams stLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        stLp.topMargin = dp(14);
        panel.addView(status, stLp);
    }

    // ------------------------------------------------------ Connect flow
    private void startConnectFlow() {
        if (adapter == null) {
            busy(false, "This device has no Bluetooth adapter.");
            return;
        }
        String[] need = missingPermissions();
        if (need.length > 0) {
            requestPermissions(need, REQ_PERMS);
            return;
        }
        if (!adapter.isEnabled()) {
            // Ask the user to turn Bluetooth on (needs BLUETOOTH_CONNECT on 31+).
            try {
                startActivityForResult(new Intent(BluetoothAdapter.ACTION_REQUEST_ENABLE), REQ_ENABLE_BT);
            } catch (SecurityException e) {
                busy(false, "Please enable Bluetooth, then tap Connect again.");
            }
            return;
        }
        beginScan();
    }

    private String[] missingPermissions() {
        List<String> need = new ArrayList<>();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.S) {
            if (!granted(Manifest.permission.BLUETOOTH_SCAN)) need.add(Manifest.permission.BLUETOOTH_SCAN);
            if (!granted(Manifest.permission.BLUETOOTH_CONNECT)) need.add(Manifest.permission.BLUETOOTH_CONNECT);
        } else {
            // Pre-12: BLE scanning requires location to be granted at runtime.
            if (!granted(Manifest.permission.ACCESS_FINE_LOCATION)) need.add(Manifest.permission.ACCESS_FINE_LOCATION);
        }
        return need.toArray(new String[0]);
    }

    private boolean granted(String perm) {
        return checkSelfPermission(perm) == PackageManager.PERMISSION_GRANTED;
    }

    @Override
    public void onRequestPermissionsResult(int requestCode, String[] permissions, int[] results) {
        super.onRequestPermissionsResult(requestCode, permissions, results);
        if (requestCode != REQ_PERMS) return;
        boolean allOk = results.length > 0;
        for (int r : results) if (r != PackageManager.PERMISSION_GRANTED) allOk = false;
        if (allOk) {
            startConnectFlow();   // re-enter now that we're allowed
        } else {
            busy(false, "Bluetooth permission is needed to find the tracker.\n"
                    + "Grant it in Settings, then tap Connect again.");
        }
    }

    @Override
    protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (requestCode == REQ_ENABLE_BT) {
            if (adapter != null && adapter.isEnabled()) beginScan();
            else busy(false, "Bluetooth is off. Turn it on, then tap Connect.");
        }
    }

    // --------------------------------------------------------------- Scanning
    private void beginScan() {
        try {
            scanner = adapter.getBluetoothLeScanner();
        } catch (SecurityException e) {
            busy(false, "Missing Bluetooth permission: " + e.getMessage());
            return;
        }
        if (scanner == null) {
            busy(false, "Bluetooth scanner unavailable. Is Bluetooth on?");
            return;
        }
        busy(true, "Scanning for a PLSChat tracker…");

        // Filter on the NUS service the firmware advertises. (Name is a fallback
        // check on the result, since not all firmwares put the name in the ADV.)
        List<ScanFilter> filters = new ArrayList<>();
        filters.add(new ScanFilter.Builder()
                .setServiceUuid(new ParcelUuid(NUS_SERVICE))
                .build());
        ScanSettings settings = new ScanSettings.Builder()
                .setScanMode(ScanSettings.SCAN_MODE_LOW_LATENCY)
                .build();

        scanCallback = new ScanCallback() {
            @Override
            public void onScanResult(int callbackType, ScanResult result) {
                if (result == null || result.getDevice() == null) return;
                onDeviceFound(result.getDevice());
            }
            @Override
            public void onScanFailed(int errorCode) {
                ui.post(() -> { stopScan(); busy(false, "Scan failed (code " + errorCode + "). Try again."); });
            }
        };

        try {
            scanning = true;
            scanner.startScan(filters, settings, scanCallback);
        } catch (SecurityException e) {
            scanning = false;
            busy(false, "Missing Bluetooth scan permission: " + e.getMessage());
            return;
        }

        // Time-box the scan so a missing tracker doesn't spin forever.
        ui.postDelayed(() -> {
            if (scanning) {
                stopScan();
                busy(false, "No PLSChat tracker found.\n"
                        + "Make sure the T1000-E is powered on and flashed with PLSChat firmware.");
            }
        }, SCAN_TIMEOUT_MS);
    }

    private void onDeviceFound(BluetoothDevice device) {
        if (!scanning) return;   // already handling one
        String nm;
        try {
            nm = device.getName();
        } catch (SecurityException e) {
            nm = null;
        }
        // The service-UUID filter already restricts to NUS peripherals; if a
        // name is present, prefer ones that look like our tracker.
        if (nm != null && !nm.startsWith(NAME_PREFIX)) {
            // A different NUS device (e.g. some other nRF gadget). Ignore it.
            return;
        }
        deviceName = (nm != null) ? nm : "PLSChat tracker";
        stopScan();
        ui.post(() -> {
            busy(true, "Connecting to " + deviceName + "…");
            connectGatt(device);
        });
    }

    private void stopScan() {
        scanning = false;
        if (scanner != null && scanCallback != null) {
            try { scanner.stopScan(scanCallback); } catch (SecurityException ignored) {}
        }
        scanCallback = null;
    }

    // ------------------------------------------------------------------ GATT
    private void connectGatt(BluetoothDevice device) {
        try {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
                gatt = device.connectGatt(this, false, gattCallback, BluetoothDevice.TRANSPORT_LE);
            } else {
                gatt = device.connectGatt(this, false, gattCallback);
            }
        } catch (SecurityException e) {
            busy(false, "Missing Bluetooth connect permission: " + e.getMessage());
        }
    }

    private final BluetoothGattCallback gattCallback = new BluetoothGattCallback() {
        @Override
        public void onConnectionStateChange(BluetoothGatt g, int gattStatus, int newState) {
            if (newState == BluetoothGatt.STATE_CONNECTED) {
                // Ask for a bigger MTU so whole lines fit in one packet, then
                // discover services from the MTU callback.
                try {
                    if (!g.requestMtu(247)) discoverSafely(g);
                } catch (SecurityException e) {
                    discoverSafely(g);
                }
            } else if (newState == BluetoothGatt.STATE_DISCONNECTED) {
                ui.post(() -> onDisconnected(gattStatus));
            }
        }

        @Override
        public void onMtuChanged(BluetoothGatt g, int newMtu, int gattStatus) {
            if (gattStatus == BluetoothGatt.GATT_SUCCESS && newMtu >= 23) mtu = newMtu;
            discoverSafely(g);
        }

        @Override
        public void onServicesDiscovered(BluetoothGatt g, int gattStatus) {
            if (gattStatus != BluetoothGatt.GATT_SUCCESS) {
                ui.post(() -> showPanel("Connected, but couldn't read the tracker's services."));
                return;
            }
            BluetoothGattService svc = g.getService(NUS_SERVICE);
            if (svc == null) {
                ui.post(() -> showPanel("This Bluetooth device isn't a PLSChat tracker "
                        + "(no Nordic UART service)."));
                return;
            }
            rxWrite = svc.getCharacteristic(NUS_RX_WRITE);
            BluetoothGattCharacteristic txNotify = svc.getCharacteristic(NUS_TX_NOTIFY);
            if (rxWrite == null || txNotify == null) {
                ui.post(() -> showPanel("Tracker is missing the expected UART characteristics."));
                return;
            }
            // Turn on notifications for device->phone traffic, then flag ready
            // once the descriptor write lands.
            enableNotifications(g, txNotify);
        }

        @Override
        public void onDescriptorWrite(BluetoothGatt g, BluetoothGattDescriptor descriptor, int gattStatus) {
            if (CCCD.equals(descriptor.getUuid())) {
                ui.post(() -> onReady());
            }
            opDone();
        }

        @Override
        public void onCharacteristicWrite(BluetoothGatt g, BluetoothGattCharacteristic ch, int gattStatus) {
            opDone();   // let the next queued write go
        }

        // Classic (pre-API-33) notify callback. Still delivered on devices
        // running Android <13; on 13+ the framework calls the value-carrying
        // overload below instead, so we implement both.
        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic ch) {
            if (!NUS_TX_NOTIFY.equals(ch.getUuid())) return;
            byte[] data = ch.getValue();
            if (data != null && data.length > 0) onBytesFromDevice(data);
        }

        // API 33+ notify callback (value delivered directly, no shared getValue()).
        @Override
        public void onCharacteristicChanged(BluetoothGatt g, BluetoothGattCharacteristic ch, byte[] value) {
            if (!NUS_TX_NOTIFY.equals(ch.getUuid())) return;
            if (value != null && value.length > 0) onBytesFromDevice(value);
        }
    };

    private void discoverSafely(BluetoothGatt g) {
        try { g.discoverServices(); } catch (SecurityException ignored) {}
    }

    private void enableNotifications(BluetoothGatt g, BluetoothGattCharacteristic txNotify) {
        try {
            g.setCharacteristicNotification(txNotify, true);
        } catch (SecurityException e) {
            ui.post(() -> showPanel("Missing Bluetooth permission to enable notifications."));
            return;
        }
        BluetoothGattDescriptor cccd = txNotify.getDescriptor(CCCD);
        if (cccd == null) {
            ui.post(() -> showPanel("Tracker UART is missing its notify descriptor."));
            return;
        }
        enqueueGatt(() -> {
            cccd.setValue(BluetoothGattDescriptor.ENABLE_NOTIFICATION_VALUE);
            try {
                if (!g.writeDescriptor(cccd)) opDone();
            } catch (SecurityException e) {
                opDone();
            }
        });
    }

    private void onReady() {
        ready = true;
        busy(false, null);
        panel.setVisibility(View.GONE);
        topBar.setVisibility(View.VISIBLE);
        web.setVisibility(View.VISIBLE);
        if (!webReady) {
            web.loadUrl("file:///android_asset/tracker.html");
        } else {
            pushState();
        }
        sendLine("WHO");   // learn our node id so the UI can show it
    }

    private void onDisconnected(int gattStatus) {
        boolean wasReady = ready;
        ready = false;
        rxWrite = null;
        gattBusy = false;
        gattQueue.clear();
        pushState();
        if (wasReady) {
            showPanel("Lost connection to the tracker."
                    + (gattStatus != 0 ? " (status " + gattStatus + ")" : ""));
        } else {
            busy(false, "Couldn't connect to the tracker."
                    + (gattStatus != 0 ? " (status " + gattStatus + ")" : "")
                    + "\nMove closer and try again.");
        }
    }

    // ------------------------------------------------ line reassembly (RX)
    private void onBytesFromDevice(byte[] data) {
        String chunk = new String(data, java.nio.charset.StandardCharsets.UTF_8);
        synchronized (rxLineBuf) {
            for (int i = 0; i < chunk.length(); i++) {
                char c = chunk.charAt(i);
                if (c == '\n' || c == '\r') {
                    if (rxLineBuf.length() > 0) {
                        String line = rxLineBuf.toString();
                        rxLineBuf.setLength(0);
                        ui.post(() -> deliverLineToUi(line));
                    }
                } else {
                    rxLineBuf.append(c);
                    if (rxLineBuf.length() > 512) rxLineBuf.setLength(0); // runaway guard
                }
            }
        }
    }

    private void deliverLineToUi(String line) {
        if (!webReady) return;
        String js = "window.__ble && window.__ble.line(" + JSONObject.quote(line) + ");";
        web.evaluateJavascript(js, null);
    }

    private void pushState() {
        if (!webReady) return;
        String js = "window.__ble && window.__ble.state(" + (ready ? "true" : "false")
                + "," + JSONObject.quote(deviceName) + ");";
        web.evaluateJavascript(js, null);
    }

    // ------------------------------------------------ command send (TX)
    /** Queue a '\n'-terminated line to the tracker, chunked to the negotiated MTU. */
    private void sendLine(String line) {
        if (!ready || gatt == null || rxWrite == null) return;
        byte[] payload = (line + "\n").getBytes(java.nio.charset.StandardCharsets.UTF_8);
        int max = Math.max(20, mtu - 3);
        for (int off = 0; off < payload.length; off += max) {
            int end = Math.min(off + max, payload.length);
            final byte[] slice = new byte[end - off];
            System.arraycopy(payload, off, slice, 0, slice.length);
            enqueueGatt(() -> {
                rxWrite.setValue(slice);
                rxWrite.setWriteType(BluetoothGattCharacteristic.WRITE_TYPE_DEFAULT);
                try {
                    if (!gatt.writeCharacteristic(rxWrite)) opDone();
                } catch (SecurityException e) {
                    opDone();
                }
            });
        }
    }

    // ------------------------------------------------ GATT op serialisation
    private void enqueueGatt(Runnable op) {
        synchronized (gattQueue) {
            gattQueue.add(op);
            if (!gattBusy) runNextGatt();
        }
    }

    private void runNextGatt() {
        synchronized (gattQueue) {
            if (gattBusy) return;
            Runnable op = gattQueue.poll();
            if (op == null) return;
            gattBusy = true;
            // GATT ops are safe from any thread, but keep them off the binder
            // callback thread by hopping to the main looper.
            ui.post(op);
        }
    }

    private void opDone() {
        synchronized (gattQueue) {
            gattBusy = false;
        }
        runNextGatt();
    }

    // --------------------------------------------------------- JS <-> native
    private class Bridge {
        @JavascriptInterface
        public void send(String text) {
            if (text == null) return;
            final String t = text;
            ui.post(() -> sendLine("TX:" + t));
        }
        @JavascriptInterface
        public void who() {
            ui.post(() -> sendLine("WHO"));
        }
        @JavascriptInterface
        public boolean connected() {
            return ready;
        }
        @JavascriptInterface
        public void reconnect() {
            ui.post(() -> showPanel(null));
        }
    }

    // ------------------------------------------------------------------- Util
    private void showPanel(String message) {
        teardownGatt();
        ready = false;
        web.setVisibility(View.GONE);
        topBar.setVisibility(View.GONE);
        panel.setVisibility(View.VISIBLE);
        busy(false, message);
        pushState();
    }

    private void teardownGatt() {
        stopScan();
        synchronized (gattQueue) { gattQueue.clear(); gattBusy = false; }
        if (gatt != null) {
            try { gatt.disconnect(); } catch (SecurityException ignored) {}
            try { gatt.close(); } catch (SecurityException ignored) {}
            gatt = null;
        }
        rxWrite = null;
    }

    private void busy(boolean on, String msg) {
        spinner.setVisibility(on ? View.VISIBLE : View.GONE);
        if (connectBtn != null) connectBtn.setEnabled(!on);
        status.setTextColor(on ? 0xFF9ca3af : 0xFFfca5a5);
        status.setText(msg == null ? "" : msg);
    }

    private Button flatButton(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextColor(0xFF67e8f9);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 13);
        b.setBackgroundColor(Color.TRANSPARENT);
        b.setPadding(dp(10), 0, dp(10), 0);
        return b;
    }

    private Button primaryButton(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextColor(0xFFffffff);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        b.setTypeface(b.getTypeface(), Typeface.BOLD);
        GradientDrawable bg = new GradientDrawable(
                GradientDrawable.Orientation.LEFT_RIGHT,
                new int[]{0xFFa855f7, 0xFFc026d3, 0xFFec4899});
        bg.setCornerRadius(dp(14));
        b.setBackground(bg);
        b.setPadding(dp(16), dp(14), dp(16), dp(14));
        return b;
    }

    private Button secondaryButton(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextColor(0xFFe4e4e7);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0x00000000);
        bg.setCornerRadius(dp(14));
        bg.setStroke(dp(1), 0xFF3a3a4d);
        b.setBackground(bg);
        b.setPadding(dp(16), dp(13), dp(16), dp(13));
        return b;
    }

    private int dp(int v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                getResources().getDisplayMetrics());
    }

    @Override
    public void onBackPressed() {
        if (web.getVisibility() == View.VISIBLE) {
            // From the chat, back returns to the connect panel rather than
            // dropping straight out of the app.
            showPanel(null);
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        teardownGatt();
        if (web != null) web.destroy();
        super.onDestroy();
    }
}
