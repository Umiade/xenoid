package org.example.cameraruntimeprobe;

import android.app.Activity;
import android.graphics.Canvas;
import android.graphics.Color;
import android.graphics.Paint;
import android.graphics.Path;
import android.os.Bundle;
import android.os.SystemClock;
import android.view.View;
import android.view.Window;
import android.view.WindowManager;

public final class FixtureActivity extends Activity {
    @Override protected void onCreate(Bundle state) {
        super.onCreate(state);
        requestWindowFeature(Window.FEATURE_NO_TITLE);
        getWindow().setFlags(WindowManager.LayoutParams.FLAG_FULLSCREEN,
                WindowManager.LayoutParams.FLAG_FULLSCREEN);
        String kind = getIntent().getStringExtra("fixture");
        setContentView(new FixtureView(this, kind == null ? "first" : kind));
    }

    private static final class FixtureView extends View {
        private static final int FIRST_BACKGROUND = Color.rgb(42, 86, 196);
        private static final int SECOND_BACKGROUND = Color.rgb(36, 172, 92);
        private static final int TOP_LEFT_COLOR = Color.rgb(232, 48, 56);
        private static final int TOP_RIGHT_COLOR = Color.rgb(48, 216, 104);
        private static final int BOTTOM_RIGHT_COLOR = Color.rgb(248, 200, 40);
        private static final int BOTTOM_LEFT_COLOR = Color.rgb(224, 64, 208);
        private static final int[] VIDEO_COLORS = {
                Color.rgb(40, 70, 210),
                Color.rgb(220, 50, 50),
                Color.rgb(40, 200, 90),
                Color.rgb(240, 190, 30),
                Color.rgb(190, 45, 210),
                Color.rgb(25, 200, 210),
                Color.rgb(235, 105, 25),
        };
        private static final int[] VIDEO_SECOND_COLORS = {
                Color.rgb(30, 200, 210),
                Color.rgb(235, 110, 20),
                Color.rgb(105, 55, 210),
                Color.rgb(130, 220, 30),
                Color.rgb(235, 65, 140),
                Color.rgb(245, 210, 210),
                Color.rgb(25, 80, 80),
        };
        private final String kind;
        private final long epoch = SystemClock.elapsedRealtime();
        private final Paint paint = new Paint(Paint.ANTI_ALIAS_FLAG);
        private final Path path = new Path();

        FixtureView(android.content.Context context, String kind) {
            super(context);
            this.kind = kind;
        }

        @Override protected void onDraw(Canvas canvas) {
            super.onDraw(canvas);
            boolean video = "video".equals(kind) || "video-second".equals(kind);
            boolean second = "second".equals(kind) || "video-second".equals(kind);
            long phase = video ? (SystemClock.elapsedRealtime() - epoch) / 100L : 0L;
            int background = video ? videoColor(phase, second)
                    : second ? SECOND_BACKGROUND : FIRST_BACKGROUND;
            canvas.drawColor(background);
            drawFiducials(canvas);
            if (video) {
                drawTimeCode(canvas, phase, second);
                postInvalidateDelayed(33L);
            } else {
                drawDirection(canvas, second);
            }
        }

        private void drawFiducials(Canvas canvas) {
            float width = getWidth();
            float height = getHeight();

            paint.setStyle(Paint.Style.FILL);
            paint.setColor(TOP_LEFT_COLOR);
            canvas.drawRect(width * 0.03f, height * 0.03f,
                    width * 0.22f, height * 0.22f, paint);
            paint.setColor(Color.BLACK);
            canvas.drawRect(width * 0.055f, height * 0.055f,
                    width * 0.095f, height * 0.095f, paint);

            paint.setColor(TOP_RIGHT_COLOR);
            canvas.drawCircle(width * 0.88f, height * 0.12f,
                    Math.min(width, height) * 0.10f, paint);

            path.reset();
            path.moveTo(width * 0.76f, height * 0.76f);
            path.lineTo(width * 0.97f, height * 0.76f);
            path.lineTo(width * 0.97f, height * 0.97f);
            path.close();
            paint.setColor(BOTTOM_RIGHT_COLOR);
            canvas.drawPath(path, paint);

            paint.setColor(BOTTOM_LEFT_COLOR);
            canvas.drawRect(width * 0.03f, height * 0.825f,
                    width * 0.21f, height * 0.895f, paint);
            canvas.drawRect(width * 0.085f, height * 0.76f,
                    width * 0.155f, height * 0.96f, paint);
        }

        private void drawDirection(Canvas canvas, boolean second) {
            float width = getWidth();
            float height = getHeight();
            path.reset();
            path.moveTo(width * 0.29f, height * 0.47f);
            path.lineTo(width * 0.57f, height * 0.47f);
            path.lineTo(width * 0.57f, height * 0.40f);
            path.lineTo(width * 0.73f, height * 0.54f);
            path.lineTo(width * 0.57f, height * 0.68f);
            path.lineTo(width * 0.57f, height * 0.61f);
            path.lineTo(width * 0.29f, height * 0.61f);
            path.close();
            paint.setColor(Color.WHITE);
            canvas.drawPath(path, paint);
            paint.setColor(Color.BLACK);
            paint.setTextAlign(Paint.Align.LEFT);
            paint.setTextSize(Math.max(38f, width / 13f));
            canvas.drawText(second ? "B" : "A", width * 0.34f,
                    height * 0.585f, paint);
        }

        private void drawTimeCode(Canvas canvas, long phase, boolean second) {
            float width = getWidth();
            float height = getHeight();
            long code = phase ^ (second ? 0x5a5L : 0L);
            float left = width * 0.25f;
            float top = height * 0.64f;
            float cell = width * 0.042f;
            for (int bit = 0; bit < 12; ++bit) {
                paint.setColor(((code >>> bit) & 1L) == 0L
                        ? Color.rgb(12, 18, 28) : Color.WHITE);
                canvas.drawRect(left + bit * cell, top,
                        left + (bit + 1) * cell - 2f, top + height * 0.08f, paint);
            }
            paint.setColor(Color.WHITE);
            paint.setTextAlign(Paint.Align.LEFT);
            paint.setTextSize(Math.max(34f, width / 16f));
            canvas.drawText((second ? "V2 " : "V1 ") + Long.toString(phase),
                    width * 0.27f, height * 0.58f, paint);
        }

        private static int videoColor(long phase, boolean second) {
            int[] colors = second ? VIDEO_SECOND_COLORS : VIDEO_COLORS;
            return colors[(int) (phase % colors.length)];
        }
    }
}
