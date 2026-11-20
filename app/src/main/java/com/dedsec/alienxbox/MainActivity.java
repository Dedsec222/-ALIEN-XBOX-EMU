package com.dedsec.alienxbox;

import android.app.Activity;
import android.content.Intent;
import android.net.Uri;
import android.os.Bundle;
import android.widget.Button;
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
    private final ExecutorService worker = Executors.newSingleThreadExecutor();
    private final Random random = new Random();
    private TextView status;
    private int request;

    @Override public void onCreate(Bundle saved) {
        super.onCreate(saved);
        ScrollView scroll = new ScrollView(this);
        LinearLayout panel = new LinearLayout(this);
        panel.setOrientation(LinearLayout.VERTICAL);
        int padding = Math.round(18 * getResources().getDisplayMetrics().density);
        panel.setPadding(padding, padding * 2, padding, padding);
        scroll.addView(panel);
        setContentView(scroll);
        TextView heading = new TextView(this);
        heading.setText("ALIEN XBOX · GENESIS 0.2");
        heading.setTextSize(23);
        panel.addView(heading);
        TextView diagnostics = new TextView(this);
        diagnostics.setText(diagnostic() + "\nAlien Doors · pick the door hiding the alien.");
        panel.addView(diagnostics);
        LinearLayout doors = new LinearLayout(this);
        panel.addView(doors);
        for (int i = 1; i <= 3; i++) {
            final int choice = i;
            Button door = new Button(this);
            door.setText("Door " + i);
            doors.addView(door);
            door.setOnClickListener(v -> launch(null, choice, random.nextInt(3) + 1));
        }
        Button open = new Button(this);
        open.setText("Open homebrew executable");
        panel.addView(open);
        open.setOnClickListener(v -> startActivityForResult(
            new Intent(Intent.ACTION_OPEN_DOCUMENT).addCategory(Intent.CATEGORY_OPENABLE)
                .setType("*/*"), 1));
        status = new TextView(this);
        status.setText("Supports single-section, freestanding AMD64 PE32+ homebrew up to 4 MiB. Xbox retail packages are unsupported.");
        panel.addView(status);
    }

    @Override protected void onActivityResult(int code, int result, Intent data) {
        super.onActivityResult(code, result, data);
        if (code == 1 && result == RESULT_OK && data != null && data.getData() != null)
            launch(data.getData(), 0, 0);
    }

    private void launch(Uri uri, int choice, int target) {
        final int current = ++request;
        status.setText("Loading executable…");
        worker.execute(() -> {
            String message;
            try (InputStream stream = uri == null ? getAssets().open("doors.exe")
                    : getContentResolver().openInputStream(uri)) {
                if (stream == null) throw new IOException("File provider returned no stream.");
                ByteArrayOutputStream data = new ByteArrayOutputStream();
                byte[] chunk = new byte[8192];
                int count;
                while ((count = stream.read(chunk)) != -1) {
                    if (data.size() + count > 4 * 1024 * 1024)
                        throw new IOException("Image exceeds 4 MiB.");
                    data.write(chunk, 0, count);
                }
                message = execute(data.toByteArray(), choice, target, uri == null);
            } catch (IOException | SecurityException ex) {
                message = "Could not load file. " + ex.getMessage();
            }
            final String text = message;
            runOnUiThread(() -> {
                if (current == request && !isDestroyed()) status.setText(text);
            });
        });
    }

    @Override protected void onDestroy() {
        worker.shutdownNow();
        super.onDestroy();
    }
}
