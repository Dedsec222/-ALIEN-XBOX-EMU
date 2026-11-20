package com.dedsec.alienxbox;

import android.app.Activity;
import android.content.Intent;
import android.content.pm.ActivityInfo;
import android.graphics.Color;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.net.Uri;
import android.os.Bundle;
import android.view.Gravity;
import android.view.View;
import android.widget.Button;
import android.widget.HorizontalScrollView;
import android.widget.LinearLayout;
import android.widget.ScrollView;
import android.widget.TextView;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class MainActivity extends Activity {
    static { System.loadLibrary("alien_core"); }
    private static native String diagnostic();
    private static native String execute(byte[] image, int choice, int target, boolean bundled);
    private static final int BG = 0xff050e11, PANEL = 0xff10262a, TEAL = 0xff32f3df;
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Random random = new Random();
    private LinearLayout content;
    private TextView status;
    private int request;

    private int dp(int value) { return Math.round(value * getResources().getDisplayMetrics().density); }
    private GradientDrawable surface(int color, int stroke) {
        GradientDrawable d = new GradientDrawable();
        d.setColor(color);
        d.setCornerRadius(dp(13));
        d.setStroke(dp(1), stroke);
        return d;
    }
    private TextView text(String value, int size, int color, boolean bold) {
        TextView t = new TextView(this);
        t.setText(value); t.setTextSize(size); t.setTextColor(color);
        if (bold) t.setTypeface(Typeface.DEFAULT, Typeface.BOLD);
        t.setGravity(Gravity.CENTER_VERTICAL);
        return t;
    }
    private LinearLayout column() {
        LinearLayout l = new LinearLayout(this);
        l.setOrientation(LinearLayout.VERTICAL);
        return l;
    }
    private void addSpace(LinearLayout parent, int height) {
        View v = new View(this); parent.addView(v, new LinearLayout.LayoutParams(1, dp(height)));
    }
    private LinearLayout card(LinearLayout parent, String title) {
        LinearLayout box = column();
        box.setPadding(dp(17), dp(14), dp(17), dp(14));
        box.setBackground(surface(PANEL, 0xff22646a));
        LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(-1, -2);
        lp.bottomMargin = dp(13); parent.addView(box, lp);
        box.addView(text(title, 16, TEAL, true));
        addSpace(box, 10);
        return box;
    }
    private Button button(String label, Runnable action) {
        Button b = new Button(this);
        b.setText(label); b.setAllCaps(false);
        b.setTextColor(0xff041618); b.setTextSize(13);
        b.setBackground(surface(TEAL, TEAL));
        b.setOnClickListener(v -> action.run());
        return b;
    }
    private void line(LinearLayout parent, String value) {
        TextView t = text(value, 13, 0xffc3e3e5, false);
        t.setPadding(0, dp(5), 0, dp(5)); parent.addView(t);
    }
    @Override public void onCreate(Bundle state) {
        super.onCreate(state);
        setRequestedOrientation(ActivityInfo.SCREEN_ORIENTATION_LANDSCAPE);
        getWindow().setStatusBarColor(BG);
        getWindow().setNavigationBarColor(BG);
        LinearLayout root = column();
        root.setBackgroundColor(BG);
        setContentView(root);
        LinearLayout header = new LinearLayout(this);
        header.setGravity(Gravity.CENTER_VERTICAL);
        header.setPadding(dp(20), dp(12), dp(20), dp(12));
        header.setBackgroundColor(0xff08191d);
        root.addView(header);
        TextView logo = text("◈  ALIEN XBOX", 24, TEAL, true);
        header.addView(logo, new LinearLayout.LayoutParams(0, -2, 1));
        header.addView(text("GENESIS 0.2  •  ARM64  •  EXPERIMENTAL", 12, 0xff9ebec2, true));
        View divider = new View(this); divider.setBackgroundColor(0xff237c7e);
        root.addView(divider, new LinearLayout.LayoutParams(-1, dp(1)));
        LinearLayout body = new LinearLayout(this);
        root.addView(body, new LinearLayout.LayoutParams(-1, 0, 1));
        LinearLayout menu = column();
        menu.setPadding(dp(12), dp(18), dp(12), dp(8));
        menu.setBackgroundColor(0xff09181c);
        body.addView(menu, new LinearLayout.LayoutParams(dp(174), -1));
        String[] names = {"Dashboard", "Homebrew", "Performance", "Graphics", "Controller", "Diagnostics"};
        for (String name : names) {
            TextView nav = text("  " + name, 14, name.equals("Dashboard") ? TEAL : 0xffb4d2d4, name.equals("Dashboard"));
            nav.setPadding(dp(5), dp(10), dp(5), dp(10));
            nav.setOnClickListener(v -> showPage(name));
            menu.addView(nav);
        }
        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        body.addView(scroll, new LinearLayout.LayoutParams(0, -1, 1));
        content = column(); content.setPadding(dp(20), dp(18), dp(20), dp(12));
        scroll.addView(content);
        showPage("Dashboard");
    }
    private void showPage(String page) {
        content.removeAllViews();
        content.addView(text(page.toUpperCase(), 21, 0xffffffff, true));
        addSpace(content, 14);
        if (page.equals("Dashboard")) {
            LinearLayout hero = card(content, "ALIEN TEAL  /  COMMAND CENTER");
            line(hero, "Native ARM64 research emulator  •  x86-64 interpreter  •  PE32+ homebrew");
            line(hero, "Xbox Series X|S retail games: NOT SUPPORTED");
            hero.addView(button("Launch Alien Doors homebrew", () -> showPage("Homebrew")));
            LinearLayout overview = card(content, "ENGINE CAPABILITIES");
            line(overview, "✓ Native C++ guest interpreter");
            line(overview, "✓ Restricted AMD64 PE32+ executable loader");
            line(overview, "✓ Vulkan loader diagnostics");
            line(overview, "○ Xbox OS / retail package loading: not implemented");
            line(overview, "○ Xbox graphics translation / game compatibility: not implemented");
        } else if (page.equals("Homebrew")) {
            LinearLayout games = card(content, "ALIEN DOORS  •  PLAYABLE HOMEBREW TEST");
            line(games, "Choose a door. The bundled x86-64 executable evaluates your choice.");
            LinearLayout doors = new LinearLayout(this);
            games.addView(doors);
            for (int i = 1; i <= 3; i++) {
                final int choice = i;
                Button door = button("DOOR " + i, () -> launch(null, choice, random.nextInt(3) + 1));
                LinearLayout.LayoutParams lp = new LinearLayout.LayoutParams(0, dp(52), 1);
                lp.setMargins(dp(3), dp(6), dp(3), dp(6)); doors.addView(door, lp);
            }
            games.addView(button("Open AMD64 PE32+ homebrew file", () ->
                startActivityForResult(new Intent(Intent.ACTION_OPEN_DOCUMENT)
                    .addCategory(Intent.CATEGORY_OPENABLE).setType("*/*"), 1)));
            status = text("Ready. Single-section, freestanding AMD64 PE32+ images up to 4 MiB only.", 13, 0xffb8e3e4, false);
            status.setPadding(0, dp(12), 0, dp(5)); games.addView(status);
        } else if (page.equals("Diagnostics")) {
            LinearLayout diagnostics = card(content, "NATIVE ENGINE DIAGNOSTICS");
            line(diagnostics, diagnostic());
            line(diagnostics, "Results are native diagnostics, not retail-game performance benchmarks.");
        } else if (page.equals("Performance")) {
            LinearLayout perf = card(content, "PERFORMANCE / EXPERIMENTAL");
            line(perf, "Host CPU: ARM64  •  Guest ISA: limited AMD64 interpretation");
            line(perf, "Instruction budget: 100,000 per homebrew launch");
            line(perf, "Stable / Performance / Alien Mode: planned, not implemented");
            line(perf, "FPS and GPU usage will appear when a graphics runtime exists.");
        } else if (page.equals("Graphics")) {
            LinearLayout graphics = card(content, "GRAPHICS BACKEND");
            line(graphics, "Vulkan loader probing is available in Diagnostics.");
            line(graphics, "Guest Xbox graphics translation: not implemented.");
            line(graphics, "Resolution scaling, shaders, FSR and frame limiting: unavailable.");
        } else {
            LinearLayout controller = card(content, "CONTROLLER / INPUT");
            line(controller, "Alien Doors currently uses touchscreen choices.");
            line(controller, "Xbox controller emulation and remapping: planned.");
            line(controller, "No guest controller API is implemented yet.");
        }
    }
    @Override protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code == 1 && result == RESULT_OK && data != null && data.getData() != null)
            launch(data.getData(), 0, 0);
    }
    private void launch(Uri uri, int choice, int target) {
        if (status == null) showPage("Homebrew");
        final int current = ++request;
        status.setText("Executing guest homebrew…");
        worker.execute(() -> {
            String message;
            try (InputStream stream = uri == null ? getAssets().open("doors.exe")
                    : getContentResolver().openInputStream(uri)) {
                if (stream == null) throw new IOException("File provider returned no stream.");
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192]; int count;
                while ((count = stream.read(chunk)) != -1) {
                    if (data.size() + count > 4 * 1024 * 1024)
                        throw new IOException("Image exceeds 4 MiB.");
                    data.write(chunk, 0, count);
                }
                message = execute(data.toByteArray(), choice, target, uri == null);
            } catch (IOException | SecurityException ex) {
                message = "Could not load file. " + ex.getMessage();
            }
            final String result = message;
            runOnUiThread(() -> {
                if (current == request && !isDestroyed() && status != null) status.setText(result);
            });
        });
    }
    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
