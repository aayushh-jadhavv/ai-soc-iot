package org.raspigateway.demo;

import android.app.Activity;
import android.app.AlertDialog;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.os.Bundle;
import android.text.InputType;
import android.view.ViewGroup;
import android.widget.Button;
import android.widget.EditText;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONException;
import java.io.IOException;
import java.net.ConnectException;
import java.net.SocketTimeoutException;
import java.net.UnknownHostException;
import java.nio.charset.StandardCharsets;
import java.text.NumberFormat;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public final class MainActivity extends Activity {
    private static final int INK = Color.rgb(16, 39, 33);
    private static final int MUTED = Color.rgb(64, 87, 80);
    private static final int GREEN = Color.rgb(23, 103, 88);
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private boolean explaining;
    private EditText address;
    private Button connect;
    private TextView status;
    private TextView source;
    private LinearLayout cards;

    @Override protected void onCreate(Bundle savedState) {
        super.onCreate(savedState);
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        LinearLayout page = column(22);
        scroll.addView(page);
        setContentView(scroll);
        page.addView(text("Gateway reports", 32, INK, true));
        TextView subtitle = text("Raspberry Pi IDS reports", 16, MUTED, false);
        add(page, subtitle, 4);

        if (BuildConfig.DEBUG) {
            add(page, text("Pi address", 16, INK, true), 22);
            address = new EditText(this);
            address.setId(100);
            address.setSingleLine(true);
            address.setInputType(InputType.TYPE_CLASS_TEXT | InputType.TYPE_TEXT_VARIATION_URI);
            address.setHint("http://192.168.1.50:8080");
            add(page, address, 4);
            connect = button("Fetch reports", true);
            connect.setOnClickListener(view -> fetch());
            add(page, connect, 8);
        }

        status = text("", 14, MUTED, false);
        status.setAccessibilityLiveRegion(TextView.ACCESSIBILITY_LIVE_REGION_POLITE);
        add(page, status, 10);
        source = text("Reports", 20, INK, true);
        add(page, source, 20);
        cards = column(0);
        page.addView(cards);
        try {
            byte[] raw = DemoClient.readBody(getAssets().open("reports.json"));
            render(new Reports(new String(raw, StandardCharsets.UTF_8)), "Bundled samples");
        } catch (IOException | JSONException error) {
            status.setText("Could not open bundled reports.");
        }
    }

    private void fetch() {
        String endpoint = address.getText().toString();
        connect.setEnabled(false);
        status.setText("Connecting to the Pi…");
        worker.execute(() -> {
            try {
                Reports reports = new Reports(DemoClient.reports(endpoint));
                runOnUiThread(() -> {
                    if (isDestroyed() || isFinishing()) return;
                    render(reports, "Fetched from Pi");
                    status.setText("Connection succeeded.");
                    connect.setEnabled(true);
                });
            } catch (IOException | JSONException error) {
                String message = connectionMessage(error);
                runOnUiThread(() -> {
                    if (isDestroyed() || isFinishing()) return;
                    status.setText(message + " The displayed reports did not change.");
                    connect.setEnabled(true);
                });
            }
        });
    }

    private String connectionMessage(Exception error) {
        if (error instanceof SocketTimeoutException) return "The Pi did not respond in time.";
        if (error instanceof ConnectException) return "Could not connect. Check the Pi address and server.";
        if (error instanceof UnknownHostException) return "Could not resolve the Pi address.";
        if (error instanceof JSONException) return "The response does not match the report format.";
        return error.getMessage() == null ? "Gateway request failed." : error.getMessage();
    }

    private void render(Reports reports, String origin) {
        source.setText(origin + (reports.live ? " · Live IDS" : " · Synthetic"));
        cards.removeAllViews();
        add(cards, text("Gateway: " + reports.gatewayId, 14, MUTED, false), 4);
        if (reports.entries.isEmpty()) {
            String message = reports.live ? "No recent IDS results yet. Check the gateway and retry."
                    : "No reports returned.";
            add(cards, text(message, 16, INK, false), 12);
        }
        for (Reports.Report report : reports.entries) {
            LinearLayout card = column(16);
            card.setBackground(background(Color.WHITE, 14));
            add(card, text(report.device, 19, INK, true), 0);
            add(card, text(report.actionLabel(), 14, GREEN, true), 5);
            add(card, text(report.summary, 16, INK, false), 8);
            Button details = button("View report", false);
            details.setContentDescription("View report for " + report.device);
            details.setOnClickListener(view -> showDetails(report));
            add(card, details, 10);
            add(cards, card, 12);
        }
    }

    private void showDetails(Reports.Report report) {
        NumberFormat format = NumberFormat.getNumberInstance();
        format.setMaximumFractionDigits(4);
        String score = report.score == null ? "Unavailable" : format.format(report.score);
        AlertDialog.Builder details = new AlertDialog.Builder(this)
                .setTitle(report.device)
                .setMessage((report.live ? "Live IDS report · " : "Synthetic report · ") + report.id + " · Revision " + report.revision
                        + "\n\n" + report.summary + "\n\nCoverage: " + report.coverage
                        + "\n\nDetector score: " + score + "\n\nRecommendation: "
                        + report.recommendation + "\n\nAction status: " + report.actionLabel()
                        + report.detectorDetails)
                .setPositiveButton("Close", null);
        if (BuildConfig.DEBUG) {
            details.setNeutralButton("Explain report", (dialog, which) -> explainReport(report));
        }
        details.show();
    }

    private void explainReport(Reports.Report report) {
        if (explaining) {
            new AlertDialog.Builder(this).setMessage("An explanation is already being generated.")
                    .setPositiveButton("OK", null).show();
            return;
        }
        explaining = true;
        AlertDialog dialog = new AlertDialog.Builder(this)
                .setTitle("AI explanation · " + report.device)
                .setMessage("Generating on this phone…")
                .setPositiveButton("Close", null)
                .show();
        worker.execute(() -> {
            String message;
            try {
                message = LocalReportExplainer.explain(getFilesDir(), report)
                        + "\n\nCompare this explanation with the original report.";
            } catch (IOException | RuntimeException | LinkageError error) {
                android.util.Log.w("GatewayReports", "Local explanation failed", error);
                String reason = error instanceof IOException
                        ? error.getMessage() : "The local model could not run.";
                message = reason + "\n\nOpen View report to read the original facts.";
            }
            String result = message;
            runOnUiThread(() -> {
                explaining = false;
                if (!isDestroyed() && !isFinishing() && dialog.isShowing()) {
                    dialog.setMessage(result);
                }
            });
        });
    }

    private LinearLayout column(int padding) {
        LinearLayout layout = new LinearLayout(this);
        layout.setOrientation(LinearLayout.VERTICAL);
        int p = dp(padding);
        layout.setPadding(p, p, p, p);
        return layout;
    }

    private TextView text(String value, int size, int color, boolean bold) {
        TextView view = new TextView(this);
        view.setText(value);
        view.setTextSize(size);
        view.setTextColor(color);
        if (bold) view.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        return view;
    }

    private Button button(String label, boolean primary) {
        Button button = new Button(this);
        button.setText(label);
        button.setAllCaps(false);
        button.setTextColor(primary ? Color.WHITE : GREEN);
        button.setBackgroundTintList(android.content.res.ColorStateList.valueOf(
                primary ? GREEN : Color.rgb(225, 241, 234)));
        button.setMinHeight(dp(48));
        return button;
    }

    private GradientDrawable background(int color, int radius) {
        GradientDrawable shape = new GradientDrawable();
        shape.setColor(color);
        shape.setCornerRadius(dp(radius));
        return shape;
    }

    private void add(LinearLayout parent, android.view.View view, int top) {
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT);
        params.topMargin = dp(top);
        parent.addView(view, params);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
