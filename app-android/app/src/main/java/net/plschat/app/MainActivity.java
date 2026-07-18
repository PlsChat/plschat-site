package net.plschat.app;

import android.app.Activity;
import android.graphics.Color;
import android.graphics.drawable.GradientDrawable;
import android.net.ConnectivityManager;
import android.net.Network;
import android.net.NetworkCapabilities;
import android.net.NetworkRequest;
import android.net.wifi.WifiNetworkSpecifier;
import android.os.Build;
import android.os.Bundle;
import android.os.Handler;
import android.os.Looper;
import android.os.PatternMatcher;
import android.text.InputType;
import android.util.TypedValue;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.webkit.WebChromeClient;
import android.webkit.WebResourceError;
import android.webkit.WebResourceRequest;
import android.webkit.WebSettings;
import android.webkit.WebView;
import android.webkit.WebViewClient;
import android.widget.Button;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.TextView;
import android.widget.Toast;

/**
 * PLSChat companion app.
 *
 * Why this app exists: a PLSChat device serves its whole UI over its own Wi-Fi
 * hotspot at http://192.168.4.1. That hotspot has no internet, so GrapheneOS
 * (and modern stock Android) refuse to route a browser's traffic to it and
 * often drop the Wi-Fi. This app fixes that by explicitly *binding its own
 * process* to the PLSChat Wi-Fi network via ConnectivityManager, so every
 * request from the embedded WebView is forced onto that link regardless of
 * whether it provides internet. The UI you see is the device's own web UI,
 * unchanged.
 */
public class MainActivity extends Activity {

    private static final String DEVICE_URL = "http://192.168.4.1/";
    private static final String SSID_PREFIX = "PLSChat-";
    private static final String DEFAULT_PASSWORD = "pls12345";

    private ConnectivityManager cm;
    private ConnectivityManager.NetworkCallback activeCallback;
    private Network boundNetwork;

    // A freshly-bound Wi-Fi link is often not route-ready for a second or two,
    // so the first page load can fail transiently. Retry a few times before
    // declaring the device unreachable, instead of tearing the connection down.
    private int loadRetries = 0;
    private static final int MAX_LOAD_RETRIES = 5;
    private static final long RETRY_DELAY_MS = 1200L;

    // Set once a direct HTTP probe (bound explicitly to the PLSChat network)
    // has confirmed the device answers at 192.168.4.1. Lets us tell "device
    // unreachable" apart from "device reachable, but WebView won't load it".
    private volatile boolean routeConfirmed = false;

    private FrameLayout root;
    private WebView web;
    private LinearLayout panel;
    private TextView status;
    private ProgressBar spinner;
    private EditText ssidField;
    private EditText passField;
    private LinearLayout topBar;

    private final Handler ui = new Handler(Looper.getMainLooper());

    @Override
    protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        cm = (ConnectivityManager) getSystemService(CONNECTIVITY_SERVICE);

        root = new FrameLayout(this);
        root.setBackgroundColor(0xFF0a0c1f);

        buildWebView();
        buildTopBar();
        buildPanel();

        // Sit the device UI *below* the top bar (not behind it) so the bar
        // doesn't cover the top of the web UI.
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
        s.setDatabaseEnabled(true);
        s.setLoadWithOverviewMode(true);
        s.setUseWideViewPort(true);
        s.setCacheMode(WebSettings.LOAD_DEFAULT);
        s.setMixedContentMode(WebSettings.MIXED_CONTENT_ALWAYS_ALLOW);
        s.setMediaPlaybackRequiresUserGesture(false);

        web.setWebViewClient(new WebViewClient() {
            @Override
            public boolean shouldOverrideUrlLoading(WebView v, String url) {
                return false; // keep all navigation inside the device UI
            }
            @Override
            public void onPageFinished(WebView v, String url) {
                // Reached the device UI — clear the retry budget for later reloads.
                if (url != null && url.startsWith("http://192.168.4.1")) {
                    loadRetries = 0;
                }
            }
            @Override
            public void onReceivedError(WebView v, WebResourceRequest request, WebResourceError error) {
                // Ignore sub-resource failures (e.g. a missing favicon); only the
                // main page failing to reach the device counts.
                if (request == null || !request.isForMainFrame()) return;
                String u = request.getUrl() != null ? request.getUrl().toString() : "";
                if (!u.startsWith("http://192.168.4.1")) return;

                if (boundNetwork != null && loadRetries < MAX_LOAD_RETRIES) {
                    loadRetries++;
                    // Give the link another moment, then try the device again.
                    ui.postDelayed(() -> {
                        if (boundNetwork != null) web.loadUrl(DEVICE_URL);
                    }, RETRY_DELAY_MS);
                } else {
                    CharSequence desc = (error != null) ? error.getDescription() : null;
                    int code = (error != null) ? error.getErrorCode() : 0;
                    String extra = routeConfirmed
                            ? "\n\nThe device WAS reachable from the app, but the in-app browser "
                              + "couldn't load it — this is a WebView routing issue, not the device."
                            : "\n\nMake sure it's powered on and try connecting again.";
                    showPanel("Couldn't reach the device at 192.168.4.1."
                            + (desc != null ? "\n(" + code + ": " + desc + ")" : "") + extra);
                }
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
        title.setText("PLSChat");
        title.setTextColor(0xFFe4e4e7);
        title.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        title.setTypeface(title.getTypeface(), android.graphics.Typeface.BOLD);
        LinearLayout.LayoutParams tlp = new LinearLayout.LayoutParams(0,
                ViewGroup.LayoutParams.WRAP_CONTENT, 1f);
        topBar.addView(title, tlp);

        Button reload = flatButton("↻ Reload");
        reload.setOnClickListener(v -> { if (web != null) web.reload(); });
        topBar.addView(reload);

        Button reconnect = flatButton("Reconnect");
        reconnect.setOnClickListener(v -> showPanel(null));
        topBar.addView(reconnect);
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
        h.setText("PLSChat");
        h.setTextColor(0xFFffffff);
        h.setTextSize(TypedValue.COMPLEX_UNIT_SP, 26);
        h.setTypeface(h.getTypeface(), android.graphics.Typeface.BOLD);
        h.setGravity(Gravity.CENTER);
        panel.addView(h);

        TextView sub = new TextView(this);
        sub.setText("Connect to your device's hotspot to open the chat interface.");
        sub.setTextColor(0xFF9ca3af);
        sub.setTextSize(TypedValue.COMPLEX_UNIT_SP, 14);
        sub.setGravity(Gravity.CENTER);
        LinearLayout.LayoutParams subLp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        subLp.topMargin = dp(6);
        subLp.bottomMargin = dp(24);
        panel.addView(sub, subLp);

        ssidField = field("Network name (optional, e.g. PLSChat-Repeater)", false);
        ssidField.setInputType(InputType.TYPE_CLASS_TEXT);
        panel.addView(ssidField, fieldLp());

        passField = field("Hotspot password", true);
        passField.setText(DEFAULT_PASSWORD);
        panel.addView(passField, fieldLp());

        Button auto = primaryButton("Connect automatically");
        auto.setOnClickListener(v -> connectViaSpecifier());
        LinearLayout.LayoutParams autoLp = fieldLp();
        autoLp.topMargin = dp(18);
        panel.addView(auto, autoLp);

        Button current = secondaryButton("I've already joined it in Settings");
        current.setOnClickListener(v -> bindToCurrentWifi());
        panel.addView(current, fieldLp());

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

        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            // WifiNetworkSpecifier is API 29+. On older devices, only the
            // "already joined" path is available.
            auto.setEnabled(false);
            auto.setAlpha(0.4f);
        }
    }

    private EditText field(String hint, boolean password) {
        EditText e = new EditText(this);
        e.setHint(hint);
        e.setHintTextColor(0xFF6b7280);
        e.setTextColor(0xFFe4e4e7);
        e.setTextSize(TypedValue.COMPLEX_UNIT_SP, 15);
        e.setPadding(dp(14), dp(14), dp(14), dp(14));
        GradientDrawable bg = new GradientDrawable();
        bg.setColor(0xFF12121f);
        bg.setCornerRadius(dp(12));
        bg.setStroke(dp(1), 0xFF2a2a3d);
        e.setBackground(bg);
        if (password) {
            e.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_VISIBLE_PASSWORD);
        }
        return e;
    }

    private Button primaryButton(String text) {
        Button b = new Button(this);
        b.setText(text);
        b.setAllCaps(false);
        b.setTextColor(0xFFffffff);
        b.setTextSize(TypedValue.COMPLEX_UNIT_SP, 16);
        b.setTypeface(b.getTypeface(), android.graphics.Typeface.BOLD);
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

    private LinearLayout.LayoutParams fieldLp() {
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        lp.topMargin = dp(10);
        return lp;
    }

    // -------------------------------------------------------- Network binding
    /** Join a PLSChat-* hotspot from inside the app (API 29+). */
    private void connectViaSpecifier() {
        if (Build.VERSION.SDK_INT < Build.VERSION_CODES.Q) {
            bindToCurrentWifi();
            return;
        }
        String pass = passField.getText().toString();
        String ssid = ssidField.getText().toString().trim();
        if (pass.length() < 8) {
            status.setText("Password looks too short (min 8 characters).");
            return;
        }
        busy(true, "Requesting connection to your PLSChat device…");

        WifiNetworkSpecifier.Builder b = new WifiNetworkSpecifier.Builder();
        if (!ssid.isEmpty()) {
            b.setSsid(ssid);
        } else {
            b.setSsidPattern(new PatternMatcher(SSID_PREFIX, PatternMatcher.PATTERN_PREFIX));
        }
        b.setWpa2Passphrase(pass);

        NetworkRequest req = new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .setNetworkSpecifier(b.build())
                .build();

        registerRequest(req, true);
    }

    /** Bind to the Wi-Fi the phone is already joined to (user joined via Settings). */
    private void bindToCurrentWifi() {
        busy(true, "Locking onto the current Wi-Fi…");
        NetworkRequest req = new NetworkRequest.Builder()
                .addTransportType(NetworkCapabilities.TRANSPORT_WIFI)
                .removeCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build();
        registerRequest(req, false);
    }

    private void registerRequest(NetworkRequest req, boolean isSpecifier) {
        clearCallback();
        final ConnectivityManager.NetworkCallback cb = new ConnectivityManager.NetworkCallback() {
            @Override
            public void onAvailable(Network network) {
                ui.post(() -> bindAndLoad(network));
            }
            @Override
            public void onUnavailable() {
                ui.post(() -> {
                    busy(false, null);
                    showPanel(isSpecifier
                            ? "No PLSChat hotspot found, or the request was declined.\n"
                              + "Check the device is on and the password is correct."
                            : "Couldn't lock onto a Wi-Fi network. Join the PLSChat "
                              + "hotspot in Settings first, then try again.");
                });
            }
            @Override
            public void onLost(Network network) {
                ui.post(() -> {
                    if (network.equals(boundNetwork)) {
                        boundNetwork = null;
                        showPanel("Lost connection to the PLSChat device.");
                    }
                });
            }
        };
        activeCallback = cb;
        try {
            // 60s timeout: enough to read the system Wi-Fi prompt and approve,
            // but a missing device won't hang forever.
            cm.requestNetwork(req, cb, 60000);
        } catch (SecurityException e) {
            busy(false, null);
            status.setText("Missing Wi-Fi permission: " + e.getMessage());
        } catch (RuntimeException e) {
            busy(false, null);
            status.setText("Connection error: " + e.getMessage());
        }
    }

    private void bindAndLoad(Network network) {
        boundNetwork = network;
        boolean ok;
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            ok = cm.bindProcessToNetwork(network);
        } else {
            ok = ConnectivityManager.setProcessDefaultNetwork(network);
        }
        if (!ok) {
            // Binding away from the default network fails when a VPN owns the
            // routing (e.g. Tor/Orbot). That's the usual cause here.
            showPanel("Couldn't route to the PLSChat device.\n\n"
                    + "This usually means a VPN or Tor (Orbot) is active — it can't reach a "
                    + "local device. Turn the VPN off, or set it to NOT route PLSChat, then try again.");
            return;
        }
        // Keep the panel up with a progress note while we verify the device is
        // actually reachable, instead of dropping into a silent blank WebView.
        busy(true, "Contacting device at 192.168.4.1…");
        probeDeviceThenLoad(network);
    }

    /**
     * Directly probe http://192.168.4.1/ over the *bound* network object (which
     * pins the socket to the PLSChat link regardless of WebView quirks). If it
     * answers, reveal the WebView and load it. If not, report the exact failure
     * so we can tell an unreachable device apart from a WebView routing problem.
     */
    private void probeDeviceThenLoad(final Network network) {
        routeConfirmed = false;
        new Thread(() -> {
            Exception err = null;
            int code = -1;
            for (int i = 0; i < 5 && !isFinishing(); i++) {
                try {
                    java.net.HttpURLConnection c =
                            (java.net.HttpURLConnection) network.openConnection(new java.net.URL(DEVICE_URL));
                    c.setConnectTimeout(6000);
                    c.setReadTimeout(6000);
                    c.setInstanceFollowRedirects(false);
                    code = c.getResponseCode();   // any HTTP reply means it's reachable
                    c.disconnect();
                    err = null;
                    break;
                } catch (Exception e) {
                    err = e;
                    try { Thread.sleep(1200); } catch (InterruptedException ignored) {}
                }
            }
            final Exception ferr = err;
            ui.post(() -> {
                if (network != boundNetwork) return;   // superseded by a newer attempt
                if (ferr == null) {
                    routeConfirmed = true;
                    busy(false, null);
                    panel.setVisibility(View.GONE);
                    topBar.setVisibility(View.VISIBLE);
                    web.setVisibility(View.VISIBLE);
                    loadRetries = 0;
                    web.loadUrl(DEVICE_URL);
                } else {
                    String msg = ferr.getClass().getSimpleName()
                            + (ferr.getMessage() != null ? ": " + ferr.getMessage() : "");
                    showPanel("Joined the Wi-Fi, but couldn't reach the device at 192.168.4.1.\n(" + msg + ")\n\n"
                            + "If you use a VPN or Tor (Orbot), it blocks access to local devices — "
                            + "turn it off, or set it to NOT route PLSChat, then try again.\n\n"
                            + "Otherwise, check the PLSChat device is powered on and showing its hotspot.");
                }
            });
        }).start();
    }

    private void clearCallback() {
        if (activeCallback != null) {
            try { cm.unregisterNetworkCallback(activeCallback); } catch (Exception ignored) {}
            activeCallback = null;
        }
    }

    // ------------------------------------------------------------------- Util
    private void busy(boolean on, String msg) {
        spinner.setVisibility(on ? View.VISIBLE : View.GONE);
        status.setTextColor(on ? 0xFF9ca3af : 0xFFfca5a5);
        status.setText(msg == null ? "" : msg);
    }

    private void showPanel(String message) {
        // Release the bound network so the phone can use normal Wi-Fi again.
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cm.bindProcessToNetwork(null);
        } else {
            ConnectivityManager.setProcessDefaultNetwork(null);
        }
        clearCallback();
        boundNetwork = null;
        web.setVisibility(View.GONE);
        topBar.setVisibility(View.GONE);
        panel.setVisibility(View.VISIBLE);
        busy(false, message);
    }

    private int dp(int v) {
        return (int) TypedValue.applyDimension(TypedValue.COMPLEX_UNIT_DIP, v,
                getResources().getDisplayMetrics());
    }

    @Override
    public void onBackPressed() {
        if (web.getVisibility() == View.VISIBLE && web.canGoBack()) {
            web.goBack();
        } else {
            super.onBackPressed();
        }
    }

    @Override
    protected void onDestroy() {
        clearCallback();
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.M) {
            cm.bindProcessToNetwork(null);
        }
        if (web != null) {
            web.destroy();
        }
        super.onDestroy();
    }
}
