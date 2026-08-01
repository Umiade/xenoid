package dev.xenoid.daemon;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.widget.Button;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.ThreadFactory;

public class MainActivity extends Activity {
    static final String EXTRA_BOOTSTRAP = "bootstrap";
    static final String EXTRA_CAMERA_SELF_TEST_RUN_ID = "cameraSelfTestRunId";
    private static final int REQUEST_PHOTO = 4101;
    private static final int REQUEST_VIDEO = 4102;
    private static final ExecutorService SETTINGS_WORKER =
            Executors.newSingleThreadExecutor(new ThreadFactory() {
                @Override public Thread newThread(Runnable runnable) {
                    Thread thread = new Thread(runnable, "camera-settings");
                    thread.setDaemon(true);
                    return thread;
                }
            });

    private static final class Ui {
        static final int COLOR_BACKGROUND = 0xfff5f3ed;
        static final int COLOR_SURFACE = 0xffebe9e2;
        static final int COLOR_SURFACE_STRONG = 0xffdeddd5;
        static final int COLOR_TEXT = 0xff202522;
        static final int COLOR_TEXT_MUTED = 0xff5c635f;
        static final int COLOR_ACCENT = 0xff2f5f52;
        static final int COLOR_ACCENT_PRESSED = 0xff244b41;
        static final int COLOR_ON_ACCENT = 0xfff5f3ed;
        static final int COLOR_BORDER = 0xffcbc9c1;
        static final int COLOR_SUCCESS = 0xff35684d;
        static final int COLOR_ERROR = 0xff963b35;
        static final int COLOR_DISABLED = 0xffd5d3cc;
        static final int COLOR_DISABLED_TEXT = 0xff858984;
        static final int COLOR_TRANSPARENT = 0x00000000;
        static final float TRACKING_EYEBROW = 0.12f;
        static final float TRACKING_LABEL = 0.10f;
        static final float LINE_HEIGHT_BODY = 1.16f;
        static final float LINE_HEIGHT_INTRO = 1.18f;
        static final int SPACE_1 = 4;
        static final int SPACE_2 = 8;
        static final int SPACE_3 = 12;
        static final int SPACE_4 = 16;
        static final int SPACE_5 = 24;
        static final int SPACE_6 = 32;
        static final int SPACE_7 = 40;
        static final int HAIRLINE = 1;
        static final int FOCUS_STROKE = 2;
        static final int STATE_FOCUSED = 16842908;
        static final int STATE_ENABLED = 16842910;
        static final int STATE_CHECKED = 16842912;
        static final int STATE_PRESSED = 16842919;
        static final int STATE_HOVERED = 16843623;
        static final int CONTROL_HEIGHT = 48;
        static final int THUMBNAIL_HEIGHT = 120;
        static final int CONTENT_MAX_WIDTH = 640;
        static final int WIDE_SCREEN = 720;
        static final int RADIUS_SMALL = 8;
        static final int RADIUS_MEDIUM = 12;
        static final int TYPE_CAPTION = 12;
        static final int TYPE_BODY = 14;
        static final int TYPE_SUBHEAD = 17;
        static final int TYPE_TITLE = 28;
        static final int BITMAP_WIDTH = 320;
        static final int BITMAP_HEIGHT = 180;
    }
    private static final class StatusSnapshot {
        final Map<String,Object> status;
        Bitmap photo;
        Bitmap video;

        StatusSnapshot(Map<String,Object> status, Bitmap photo, Bitmap video) {
            this.status = status;
            this.photo = photo;
            this.video = video;
        }

        void recycle() {
            if (photo != null && !photo.isRecycled()) photo.recycle();
            if (video != null && !video.isRecycled()) video.recycle();
            photo = null;
            video = null;
        }
    }


    private CameraMediaManager mediaManager;
    private TextView activationText;
    private TextView photoStatus;
    private TextView videoStatus;
    private TextView progressText;
    private ImageView photoThumbnail;
    private ImageView videoThumbnail;
    private ProgressBar progressBar;
    private Button selectPhoto;
    private Button clearPhoto;
    private Button selectVideo;
    private Button clearVideo;
    private RadioButton naturalizedMode;
    private RadioButton faithfulMode;
    private Bitmap photoBitmap;
    private Bitmap videoBitmap;
    private boolean photoConfigured;
    private boolean videoConfigured;
    private boolean busy;
    private boolean bindingStatus;
    private boolean settingsMode;
    private boolean hasResumed;
    private volatile boolean destroyed;
    private boolean managerInitializationQueued;
    private String operationError;

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        startForegroundService(new Intent(this, XenoidDaemonService.class));

        Intent intent = getIntent();
        if (intent != null && intent.getBooleanExtra(EXTRA_BOOTSTRAP, false)) {
            moveTaskToBack(true);
            finish();
            return;
        }

        if (intent != null && intent.hasExtra(EXTRA_CAMERA_SELF_TEST_RUN_ID)) {
            String runId;
            try {
                runId = intent.getStringExtra(EXTRA_CAMERA_SELF_TEST_RUN_ID);
            } catch (RuntimeException ignored) {
                finish();
                return;
            }
            boolean accepted = CameraSelfTest.startAuthorized(this, runId, new Runnable() {
                @Override public void run() { finish(); }
            });
            if (!accepted) finish();
            return;
        }

        settingsMode = true;
        buildSettingsScreen();
        initializeMediaManager();
    }

    @Override protected void onResume() {
        super.onResume();
        if (!settingsMode) return;
        if (hasResumed && !busy) {
            if (mediaManager == null) initializeMediaManager();
            else refreshStatus("Refreshing camera status...");
        }
        hasResumed = true;
    }

    @Override protected void onDestroy() {
        destroyed = true;
        releaseBitmap(photoThumbnail, photoBitmap);
        releaseBitmap(videoThumbnail, videoBitmap);
        photoBitmap = null;
        videoBitmap = null;
        super.onDestroy();
    }

    @Override protected void onActivityResult(int requestCode, int resultCode, Intent data) {
        super.onActivityResult(requestCode, resultCode, data);
        if (resultCode != RESULT_OK || data == null || data.getData() == null) return;
        final String kind;
        final String progress;
        final String failure;
        if (requestCode == REQUEST_PHOTO) {
            kind = "photo";
            progress = "Importing photo...";
            failure = "Photo could not be imported. The previous source is still active.";
        } else if (requestCode == REQUEST_VIDEO) {
            kind = "video";
            progress = "Importing video...";
            failure = "Video could not be imported. The previous source is still active.";
        } else {
            return;
        }

        ParcelFileDescriptor descriptor;
        try {
            descriptor = getContentResolver().openFileDescriptor(data.getData(), "r");
        } catch (Throwable ignored) {
            descriptor = null;
        }
        if (descriptor == null) {
            operationError = failure;
            renderActivation(null);
            return;
        }

        final ParcelFileDescriptor selected = descriptor;
        boolean queued = runManagerOperation(progress, failure, new ManagerOperation() {
            @Override public Map<String,Object> run() {
                return mediaManager.importDocument(kind, selected);
            }
        });
        if (!queued) closeDescriptor(selected);
    }

    private void buildSettingsScreen() {
        setTitle("Camera sources");
        Window window = getWindow();
        window.setStatusBarColor(Ui.COLOR_BACKGROUND);
        window.setNavigationBarColor(Ui.COLOR_BACKGROUND);
        if (Build.VERSION.SDK_INT >= 26) {
            window.getDecorView().setSystemUiVisibility(
                    View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR | View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR);
        }

        ScrollView scroll = new ScrollView(this);
        scroll.setFillViewport(true);
        scroll.setBackgroundColor(Ui.COLOR_BACKGROUND);
        scroll.setClipToPadding(false);

        FrameLayout viewport = new FrameLayout(this);
        scroll.addView(viewport, new ScrollView.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, ViewGroup.LayoutParams.WRAP_CONTENT));

        LinearLayout content = new LinearLayout(this);
        content.setOrientation(LinearLayout.VERTICAL);
        int horizontalPadding = dp(Ui.SPACE_5);
        content.setPadding(horizontalPadding, dp(Ui.SPACE_6),
                horizontalPadding, dp(Ui.SPACE_7));
        int screenWidth = getResources().getConfiguration().screenWidthDp;
        FrameLayout.LayoutParams contentParams = new FrameLayout.LayoutParams(
                screenWidth >= Ui.WIDE_SCREEN ? dp(Ui.CONTENT_MAX_WIDTH)
                        : ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
        contentParams.gravity = Gravity.TOP | Gravity.CENTER_HORIZONTAL;
        viewport.addView(content, contentParams);

        TextView eyebrow = createText("CAMERA CONTROL", Ui.TYPE_CAPTION,
                Ui.COLOR_ACCENT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        eyebrow.setLetterSpacing(Ui.TRACKING_EYEBROW);
        content.addView(eyebrow);

        TextView title = createText("Camera sources", Ui.TYPE_TITLE,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams titleParams = wrap();
        titleParams.topMargin = dp(Ui.SPACE_2);
        content.addView(title, titleParams);
        markHeading(title);

        TextView intro = createText(
                "Choose the photo and video that camera apps receive. Source details stay private on this device.",
                Ui.TYPE_BODY, Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        intro.setLineSpacing(0f, Ui.LINE_HEIGHT_INTRO);
        LinearLayout.LayoutParams introParams = wrap();
        introParams.topMargin = dp(Ui.SPACE_2);
        content.addView(intro, introParams);

        LinearLayout activationPanel = new LinearLayout(this);
        activationPanel.setOrientation(LinearLayout.VERTICAL);
        activationPanel.setPadding(dp(Ui.SPACE_4), dp(Ui.SPACE_3),
                dp(Ui.SPACE_4), dp(Ui.SPACE_3));
        activationPanel.setBackground(shape(Ui.COLOR_SURFACE, Ui.RADIUS_MEDIUM,
                Ui.COLOR_BORDER, Ui.HAIRLINE));
        LinearLayout.LayoutParams activationParams = match();
        activationParams.topMargin = dp(Ui.SPACE_5);
        content.addView(activationPanel, activationParams);

        TextView activationLabel = createText("ACTIVATION", Ui.TYPE_CAPTION,
                Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        activationLabel.setLetterSpacing(Ui.TRACKING_LABEL);
        activationPanel.addView(activationLabel);
        activationText = createText("Loading status...", Ui.TYPE_BODY,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams activationTextParams = wrap();
        activationTextParams.topMargin = dp(Ui.SPACE_1);
        activationPanel.addView(activationText, activationTextParams);

        LinearLayout progressRow = new LinearLayout(this);
        progressRow.setGravity(Gravity.CENTER_VERTICAL);
        LinearLayout.LayoutParams progressRowParams = match();
        progressRowParams.topMargin = dp(Ui.SPACE_3);
        content.addView(progressRow, progressRowParams);
        progressBar = new ProgressBar(this);
        progressBar.setIndeterminate(true);
        progressBar.setContentDescription("Camera settings operation in progress");
        LinearLayout.LayoutParams progressParams =
                new LinearLayout.LayoutParams(dp(Ui.SPACE_5), dp(Ui.SPACE_5));
        progressRow.addView(progressBar, progressParams);
        progressText = createText("Loading camera status...", Ui.TYPE_BODY,
                Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        LinearLayout.LayoutParams progressTextParams = wrap();
        progressTextParams.leftMargin = dp(Ui.SPACE_2);
        progressRow.addView(progressText, progressTextParams);

        addDivider(content);
        addPhotoSection(content);
        addDivider(content);
        addVideoSection(content);
        addDivider(content);
        addModeSection(content);

        TextView nextOpen = createText(
                "Changes take effect on the next camera open.",
                Ui.TYPE_BODY, Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        nextOpen.setPadding(dp(Ui.SPACE_4), dp(Ui.SPACE_3),
                dp(Ui.SPACE_4), dp(Ui.SPACE_3));
        nextOpen.setBackground(shape(Ui.COLOR_SURFACE, Ui.RADIUS_SMALL,
                Ui.COLOR_BORDER, Ui.HAIRLINE));
        LinearLayout.LayoutParams nextOpenParams = match();
        nextOpenParams.topMargin = dp(Ui.SPACE_6);
        content.addView(nextOpen, nextOpenParams);

        setContentView(scroll);
        setBusy(true, "Loading camera status...");
    }

    private void addPhotoSection(LinearLayout content) {
        TextView heading = createText("Photo", Ui.TYPE_SUBHEAD, Ui.COLOR_TEXT,
                Typeface.create("sans-serif-medium", Typeface.NORMAL));
        content.addView(heading);
        markHeading(heading);

        photoStatus = createText(
                "No photo selected. Select an image to use for still captures.",
                Ui.TYPE_BODY, Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        photoStatus.setLineSpacing(0f, Ui.LINE_HEIGHT_BODY);
        LinearLayout.LayoutParams statusParams = match();
        statusParams.topMargin = dp(Ui.SPACE_2);
        content.addView(photoStatus, statusParams);

        photoThumbnail = createThumbnailView(
                "Preview of the configured photo");
        LinearLayout.LayoutParams thumbnailParams =
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        dp(Ui.THUMBNAIL_HEIGHT));
        thumbnailParams.topMargin = dp(Ui.SPACE_3);
        content.addView(photoThumbnail, thumbnailParams);

        LinearLayout controls = createControlRow();
        LinearLayout.LayoutParams controlsParams = match();
        controlsParams.topMargin = dp(Ui.SPACE_3);
        content.addView(controls, controlsParams);
        selectPhoto = createButton("Select photo", true);
        clearPhoto = createButton("Clear photo", false);
        controls.addView(selectPhoto, weightedButton(false));
        controls.addView(clearPhoto, weightedButton(true));
        selectPhoto.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { openDocument("photo"); }
        });
        clearPhoto.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                runManagerOperation("Clearing photo...",
                        "Photo could not be cleared. The previous source is still active.",
                        new ManagerOperation() {
                            @Override public Map<String,Object> run() {
                                return mediaManager.clear("photo");
                            }
                        });
            }
        });
    }

    private void addVideoSection(LinearLayout content) {
        TextView heading = createText("Video", Ui.TYPE_SUBHEAD, Ui.COLOR_TEXT,
                Typeface.create("sans-serif-medium", Typeface.NORMAL));
        content.addView(heading);
        markHeading(heading);

        videoStatus = createText(
                "No video selected. Select a clip to use for video capture.",
                Ui.TYPE_BODY, Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        videoStatus.setLineSpacing(0f, Ui.LINE_HEIGHT_BODY);
        LinearLayout.LayoutParams statusParams = match();
        statusParams.topMargin = dp(Ui.SPACE_2);
        content.addView(videoStatus, statusParams);

        videoThumbnail = createThumbnailView(
                "Preview of the configured video's first frame");
        LinearLayout.LayoutParams thumbnailParams =
                new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                        dp(Ui.THUMBNAIL_HEIGHT));
        thumbnailParams.topMargin = dp(Ui.SPACE_3);
        content.addView(videoThumbnail, thumbnailParams);

        LinearLayout controls = createControlRow();
        LinearLayout.LayoutParams controlsParams = match();
        controlsParams.topMargin = dp(Ui.SPACE_3);
        content.addView(controls, controlsParams);
        selectVideo = createButton("Select video", true);
        clearVideo = createButton("Clear video", false);
        controls.addView(selectVideo, weightedButton(false));
        controls.addView(clearVideo, weightedButton(true));
        selectVideo.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { openDocument("video"); }
        });
        clearVideo.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                runManagerOperation("Clearing video...",
                        "Video could not be cleared. The previous source is still active.",
                        new ManagerOperation() {
                            @Override public Map<String,Object> run() {
                                return mediaManager.clear("video");
                            }
                        });
            }
        });
    }

    private void addModeSection(LinearLayout content) {
        TextView heading = createText("Rendering mode", Ui.TYPE_SUBHEAD, Ui.COLOR_TEXT,
                Typeface.create("sans-serif-medium", Typeface.NORMAL));
        content.addView(heading);
        markHeading(heading);

        TextView description = createText(
                "Naturalized adds subtle sensor variation. Faithful keeps only required decoding and camera transforms.",
                Ui.TYPE_BODY, Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        description.setLineSpacing(0f, Ui.LINE_HEIGHT_BODY);
        LinearLayout.LayoutParams descriptionParams = match();
        descriptionParams.topMargin = dp(Ui.SPACE_2);
        content.addView(description, descriptionParams);

        RadioGroup modeGroup = new RadioGroup(this);
        modeGroup.setOrientation(RadioGroup.VERTICAL);
        LinearLayout.LayoutParams modeParams = match();
        modeParams.topMargin = dp(Ui.SPACE_3);
        content.addView(modeGroup, modeParams);

        naturalizedMode = createModeButton(
                "Naturalized\nSubtle variation between captures");
        faithfulMode = createModeButton(
                "Faithful\nSource frames remain visually consistent");
        modeGroup.addView(naturalizedMode, match());
        LinearLayout.LayoutParams faithfulParams = match();
        faithfulParams.topMargin = dp(Ui.SPACE_1);
        modeGroup.addView(faithfulMode, faithfulParams);
        modeGroup.setOnCheckedChangeListener(new RadioGroup.OnCheckedChangeListener() {
            @Override public void onCheckedChanged(RadioGroup group, int checkedId) {
                if (bindingStatus || busy || checkedId == View.NO_ID) return;
                final String mode = checkedId == faithfulMode.getId()
                        ? "faithful" : "naturalized";
                runManagerOperation("Updating rendering mode...",
                        "Rendering mode could not be changed. The previous mode is still active.",
                        new ManagerOperation() {
                            @Override public Map<String,Object> run() {
                                return mediaManager.setMode(mode);
                            }
                        });
            }
        });
    }

    private void openDocument(String kind) {
        if (busy || mediaManager == null) return;
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        picker.setType("photo".equals(kind) ? "image/*" : "video/*");
        try {
            startActivityForResult(picker, "photo".equals(kind) ? REQUEST_PHOTO : REQUEST_VIDEO);
        } catch (ActivityNotFoundException ignored) {
            operationError = "No document picker is available.";
            renderActivation(null);
        }
    }

    private void initializeMediaManager() {
        if (destroyed || mediaManager != null || managerInitializationQueued) return;
        managerInitializationQueued = true;
        setBusy(true, "Loading camera status...");
        final android.content.Context appContext = getApplicationContext();
        try {
            SETTINGS_WORKER.execute(new Runnable() {
                @Override public void run() {
                    CameraMediaManager loadedManager = null;
                    StatusSnapshot snapshot;
                    try {
                        loadedManager = CameraMediaManager.get(appContext);
                        snapshot = loadStatusSnapshot(loadedManager, loadedManager.status());
                    } catch (Throwable ignored) {
                        snapshot = new StatusSnapshot(unavailableStatus(), null, null);
                    }
                    final CameraMediaManager finishedManager = loadedManager;
                    final StatusSnapshot finishedSnapshot = snapshot;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            managerInitializationQueued = false;
                            if (destroyed) {
                                finishedSnapshot.recycle();
                                return;
                            }
                            mediaManager = finishedManager;
                            operationError = finishedManager == null
                                    ? "Camera status is unavailable." : null;
                            renderStatus(finishedSnapshot);
                            setBusy(false, null);
                        }
                    });
                }
            });
        } catch (RuntimeException ignored) {
            managerInitializationQueued = false;
            operationError = "Camera status is unavailable.";
            renderStatus(new StatusSnapshot(unavailableStatus(), null, null));
            setBusy(false, null);
        }
    }

    private void refreshStatus(final String progressLabel) {
        final CameraMediaManager manager = mediaManager;
        if (destroyed || manager == null) return;
        setBusy(true, progressLabel);
        try {
            SETTINGS_WORKER.execute(new Runnable() {
                @Override public void run() {
                    StatusSnapshot snapshot;
                    try {
                        snapshot = loadStatusSnapshot(manager, manager.status());
                    } catch (Throwable ignored) {
                        snapshot = new StatusSnapshot(unavailableStatus(), null, null);
                    }
                    final StatusSnapshot finished = snapshot;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            if (destroyed) {
                                finished.recycle();
                                return;
                            }
                            renderStatus(finished);
                            setBusy(false, null);
                        }
                    });
                }
            });
        } catch (RuntimeException ignored) {
            operationError = "Camera status is unavailable.";
            renderStatus(new StatusSnapshot(unavailableStatus(), null, null));
            setBusy(false, null);
        }
    }

    private boolean runManagerOperation(String progressLabel, final String failureMessage,
                                        final ManagerOperation operation) {
        if (destroyed || mediaManager == null) return false;
        setBusy(true, progressLabel);
        try {
            SETTINGS_WORKER.execute(new Runnable() {
                @Override public void run() {
                    boolean succeeded = false;
                    StatusSnapshot snapshot;
                    try {
                        Map<String,Object> result = operation.run();
                        succeeded = result != null && flag(result, "ok");
                        snapshot = loadStatusSnapshot(mediaManager, mediaManager.status());
                    } catch (Throwable ignored) {
                        snapshot = new StatusSnapshot(unavailableStatus(), null, null);
                    }
                    final boolean operationSucceeded = succeeded;
                    final StatusSnapshot finished = snapshot;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            if (destroyed) {
                                finished.recycle();
                                return;
                            }
                            operationError = operationSucceeded ? null : failureMessage;
                            renderStatus(finished);
                            setBusy(false, null);
                            if (!operationSucceeded && activationText != null) {
                                activationText.announceForAccessibility(failureMessage);
                            }
                        }
                    });
                }
            });
            return true;
        } catch (RuntimeException ignored) {
            operationError = failureMessage;
            renderActivation(null);
            setBusy(false, null);
            return false;
        }
    }

    private StatusSnapshot loadStatusSnapshot(
            CameraMediaManager manager, Map<String,Object> status) {
        if (status == null) status = unavailableStatus();
        Bitmap photo = flag(status, "photoConfigured")
                ? manager.loadConfiguredThumbnail(
                        "photo", Ui.BITMAP_WIDTH, Ui.BITMAP_HEIGHT) : null;
        Bitmap video = flag(status, "videoConfigured")
                ? manager.loadConfiguredThumbnail(
                        "video", Ui.BITMAP_WIDTH, Ui.BITMAP_HEIGHT) : null;
        return new StatusSnapshot(status, photo, video);
    }

    private void renderStatus(StatusSnapshot snapshot) {
        Map<String,Object> status = snapshot == null ? unavailableStatus() : snapshot.status;
        if (status == null) status = unavailableStatus();
        Bitmap photoPreview = snapshot == null ? null : snapshot.photo;
        Bitmap videoPreview = snapshot == null ? null : snapshot.video;
        if (snapshot != null) {
            snapshot.photo = null;
            snapshot.video = null;
        }
        photoConfigured = flag(status, "photoConfigured");
        videoConfigured = flag(status, "videoConfigured");
        int photoWidth = positiveInt(status.get("photoWidth"));
        int photoHeight = positiveInt(status.get("photoHeight"));
        int videoWidth = positiveInt(status.get("videoWidth"));
        int videoHeight = positiveInt(status.get("videoHeight"));
        long durationMs = positiveLong(status.get("videoDurationMs"));
        int videoRotation = positiveInt(status.get("videoRotation"));

        if (photoConfigured) {
            String dimensions = dimensions(photoWidth, photoHeight);
            photoStatus.setText(dimensions.length() == 0
                    ? "Configured and ready for still capture."
                    : "Configured - " + dimensions);
            if (photoPreview != null) {
                showPhotoThumbnail(
                        photoPreview, dimensions.length() == 0 ? "Configured" : dimensions);
                photoPreview = null;
            } else {
                hidePhotoThumbnail();
            }
        } else {
            photoStatus.setText(
                    "No photo selected. Select an image to use for still captures.");
            hidePhotoThumbnail();
        }

        if (videoConfigured) {
            String dimensions = dimensions(videoWidth, videoHeight);
            String duration = duration(durationMs);
            String codec = displayCodec(status.get("videoCodec"));
            StringBuilder summary = new StringBuilder("Configured");
            if (dimensions.length() > 0) summary.append(" - ").append(dimensions);
            if (duration.length() > 0) summary.append(" - ").append(duration);
            if (codec.length() > 0) summary.append(" - ").append(codec);
            if (videoRotation == 90 || videoRotation == 180 || videoRotation == 270) {
                summary.append(" - ").append(videoRotation).append(" degree rotation");
            }
            videoStatus.setText(summary.toString());
            String thumbnailDetail = duration.length() > 0 ? duration
                    : (dimensions.length() > 0 ? dimensions : "Configured");
            if (videoPreview != null) {
                showVideoThumbnail(videoPreview, thumbnailDetail);
                videoPreview = null;
            } else {
                hideVideoThumbnail();
            }
        } else {
            videoStatus.setText(
                    "No video selected. Select a clip to use for video capture.");
            hideVideoThumbnail();
        }

        if (photoPreview != null && !photoPreview.isRecycled()) photoPreview.recycle();
        if (videoPreview != null && !videoPreview.isRecycled()) videoPreview.recycle();
        String mode = string(status.get("mode"));
        bindingStatus = true;
        if ("faithful".equals(mode)) {
            faithfulMode.setChecked(true);
        } else {
            naturalizedMode.setChecked(true);
        }
        bindingStatus = false;
        renderActivation(status);
        updateControls();
    }

    private void renderActivation(Map<String,Object> status) {
        if (activationText == null) return;
        boolean ok = status != null && flag(status, "ok");
        boolean active = status != null && flag(status, "active");
        String lastError = status == null ? "" : string(status.get("lastError"));
        long generation = status == null ? 0L : positiveLong(status.get("generation"));

        String text;
        int color;
        if (operationError != null) {
            text = operationError;
            color = Ui.COLOR_ERROR;
        } else if (lastError.length() > 0 || !ok) {
            text = "Activation needs attention. The previous active camera state is unchanged.";
            color = Ui.COLOR_ERROR;
        } else if (active) {
            text = generation > 0L
                    ? "Active - generation " + generation
                    : "Active and ready for the next camera open.";
            color = Ui.COLOR_SUCCESS;
        } else {
            text = "Saved, but not currently active.";
            color = Ui.COLOR_TEXT_MUTED;
        }
        activationText.setText(text);
        activationText.setTextColor(color);
    }

    private void setBusy(boolean isBusy, String label) {
        busy = isBusy;
        if (progressBar != null) {
            progressBar.setVisibility(isBusy ? View.VISIBLE : View.GONE);
            progressText.setVisibility(isBusy ? View.VISIBLE : View.GONE);
            if (label != null) progressText.setText(label);
        }
        updateControls();
    }

    private void updateControls() {
        if (selectPhoto == null) return;
        boolean managerReady = mediaManager != null;
        selectPhoto.setEnabled(!busy && managerReady);
        selectVideo.setEnabled(!busy && managerReady);
        clearPhoto.setEnabled(!busy && managerReady && photoConfigured);
        clearVideo.setEnabled(!busy && managerReady && videoConfigured);
        naturalizedMode.setEnabled(!busy && managerReady);
        faithfulMode.setEnabled(!busy && managerReady);
    }

    private ImageView createThumbnailView(String contentDescription) {
        ImageView image = new ImageView(this);
        image.setScaleType(ImageView.ScaleType.CENTER_CROP);
        image.setContentDescription(contentDescription);
        image.setBackground(shape(Ui.COLOR_SURFACE, Ui.RADIUS_SMALL,
                Ui.COLOR_BORDER, Ui.HAIRLINE));
        image.setVisibility(View.GONE);
        return image;
    }

    private void showPhotoThumbnail(Bitmap preview, String detail) {
        releaseBitmap(photoThumbnail, photoBitmap);
        photoBitmap = preview;
        photoThumbnail.setImageBitmap(photoBitmap);
        photoThumbnail.setContentDescription(
                "Configured photo preview, " + detail);
        photoThumbnail.setVisibility(View.VISIBLE);
    }

    private void showVideoThumbnail(Bitmap preview, String detail) {
        releaseBitmap(videoThumbnail, videoBitmap);
        videoBitmap = preview;
        videoThumbnail.setImageBitmap(videoBitmap);
        videoThumbnail.setContentDescription(
                "Configured video first-frame preview, " + detail);
        videoThumbnail.setVisibility(View.VISIBLE);
    }

    private void hidePhotoThumbnail() {
        releaseBitmap(photoThumbnail, photoBitmap);
        photoBitmap = null;
        photoThumbnail.setVisibility(View.GONE);
    }

    private void hideVideoThumbnail() {
        releaseBitmap(videoThumbnail, videoBitmap);
        videoBitmap = null;
        videoThumbnail.setVisibility(View.GONE);
    }


    private void releaseBitmap(ImageView view, Bitmap bitmap) {
        if (view != null) view.setImageDrawable(null);
        if (bitmap != null && !bitmap.isRecycled()) bitmap.recycle();
    }
    private static void closeDescriptor(ParcelFileDescriptor descriptor) {
        if (descriptor != null) {
            try { descriptor.close(); } catch (Throwable ignored) { }
        }
    }

    private LinearLayout createControlRow() {
        LinearLayout row = new LinearLayout(this);
        row.setOrientation(LinearLayout.HORIZONTAL);
        row.setGravity(Gravity.CENTER_VERTICAL);
        return row;
    }

    private Button createButton(String label, boolean primary) {
        Button button = new Button(this);
        button.setText(label);
        button.setTextSize(Ui.TYPE_BODY);
        button.setTypeface(Typeface.create("sans-serif-medium", Typeface.NORMAL));
        button.setAllCaps(false);
        button.setGravity(Gravity.CENTER);
        button.setMinHeight(dp(Ui.CONTROL_HEIGHT));
        button.setMinimumHeight(dp(Ui.CONTROL_HEIGHT));
        button.setPadding(dp(Ui.SPACE_3), 0, dp(Ui.SPACE_3), 0);
        button.setElevation(0f);
        button.setStateListAnimator(null);
        button.setBackground(buttonBackground(primary));
        button.setTextColor(buttonText(primary));
        return button;
    }

    private RadioButton createModeButton(String label) {
        RadioButton button = new RadioButton(this);
        button.setId(View.generateViewId());
        button.setText(label);
        button.setTextSize(Ui.TYPE_BODY);
        button.setTextColor(new ColorStateList(
                new int[][] {
                        new int[] { -Ui.STATE_ENABLED },
                        new int[] {}
                },
                new int[] { Ui.COLOR_DISABLED_TEXT, Ui.COLOR_TEXT }));
        button.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        button.setGravity(Gravity.CENTER_VERTICAL);
        button.setMinHeight(dp(Ui.CONTROL_HEIGHT));
        button.setPadding(dp(Ui.SPACE_2), dp(Ui.SPACE_1),
                dp(Ui.SPACE_2), dp(Ui.SPACE_1));
        button.setButtonTintList(new ColorStateList(
                new int[][] {
                        new int[] { Ui.STATE_CHECKED },
                        new int[] { -Ui.STATE_ENABLED },
                        new int[] {}
                },
                new int[] { Ui.COLOR_ACCENT, Ui.COLOR_DISABLED_TEXT, Ui.COLOR_TEXT_MUTED }));
        return button;
    }

    private StateListDrawable buttonBackground(boolean primary) {
        StateListDrawable states = new StateListDrawable();
        states.addState(new int[] { -Ui.STATE_ENABLED },
                shape(Ui.COLOR_DISABLED, Ui.RADIUS_SMALL,
                        Ui.COLOR_DISABLED, Ui.HAIRLINE));
        states.addState(new int[] { Ui.STATE_PRESSED },
                shape(primary ? Ui.COLOR_ACCENT_PRESSED : Ui.COLOR_SURFACE_STRONG,
                        Ui.RADIUS_SMALL, Ui.COLOR_ACCENT, Ui.HAIRLINE));
        states.addState(new int[] { Ui.STATE_FOCUSED },
                shape(primary ? Ui.COLOR_ACCENT : Ui.COLOR_SURFACE,
                        Ui.RADIUS_SMALL, Ui.COLOR_ACCENT, Ui.FOCUS_STROKE));
        states.addState(new int[] { Ui.STATE_HOVERED },
                shape(primary ? Ui.COLOR_ACCENT_PRESSED : Ui.COLOR_SURFACE_STRONG,
                        Ui.RADIUS_SMALL, Ui.COLOR_ACCENT, Ui.HAIRLINE));
        states.addState(new int[] {},
                shape(primary ? Ui.COLOR_ACCENT : Ui.COLOR_TRANSPARENT,
                        Ui.RADIUS_SMALL, primary ? Ui.COLOR_ACCENT : Ui.COLOR_BORDER,
                        Ui.HAIRLINE));
        return states;
    }

    private ColorStateList buttonText(boolean primary) {
        return new ColorStateList(
                new int[][] {
                        new int[] { -Ui.STATE_ENABLED },
                        new int[] {}
                },
                new int[] {
                        Ui.COLOR_DISABLED_TEXT,
                        primary ? Ui.COLOR_ON_ACCENT : Ui.COLOR_ACCENT
                });
    }

    private GradientDrawable shape(int fill, int radiusDp, int stroke, int strokeDp) {
        GradientDrawable drawable = new GradientDrawable();
        drawable.setColor(fill);
        drawable.setCornerRadius(dp(radiusDp));
        drawable.setStroke(dp(strokeDp), stroke);
        return drawable;
    }

    private TextView createText(String text, int sizeSp, int color, Typeface typeface) {
        TextView view = new TextView(this);
        view.setText(text);
        view.setTextSize(sizeSp);
        view.setTextColor(color);
        view.setTypeface(typeface);
        view.setIncludeFontPadding(false);
        return view;
    }

    private void addDivider(LinearLayout content) {
        View divider = new View(this);
        divider.setBackgroundColor(Ui.COLOR_BORDER);
        LinearLayout.LayoutParams params = new LinearLayout.LayoutParams(
                ViewGroup.LayoutParams.MATCH_PARENT, dp(Ui.HAIRLINE));
        params.topMargin = dp(Ui.SPACE_6);
        params.bottomMargin = dp(Ui.SPACE_6);
        content.addView(divider, params);
    }

    private LinearLayout.LayoutParams weightedButton(boolean trailing) {
        LinearLayout.LayoutParams params =
                new LinearLayout.LayoutParams(0, dp(Ui.CONTROL_HEIGHT), 1f);
        if (trailing) params.leftMargin = dp(Ui.SPACE_2);
        return params;
    }

    private LinearLayout.LayoutParams wrap() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.WRAP_CONTENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private LinearLayout.LayoutParams match() {
        return new LinearLayout.LayoutParams(ViewGroup.LayoutParams.MATCH_PARENT,
                ViewGroup.LayoutParams.WRAP_CONTENT);
    }

    private void markHeading(TextView heading) {
        if (Build.VERSION.SDK_INT >= 28) heading.setAccessibilityHeading(true);
    }

    private int dp(int value) {
        return Math.round(value * getResources().getDisplayMetrics().density);
    }

    private static boolean flag(Map<String,Object> map, String key) {
        return map != null && Boolean.TRUE.equals(map.get(key));
    }

    private static String string(Object value) {
        return value instanceof String ? (String) value : "";
    }

    private static int positiveInt(Object value) {
        if (!(value instanceof Number)) return 0;
        long number = ((Number) value).longValue();
        return number > 0L && number <= Integer.MAX_VALUE ? (int) number : 0;
    }

    private static long positiveLong(Object value) {
        if (!(value instanceof Number)) return 0L;
        long number = ((Number) value).longValue();
        return number > 0L ? number : 0L;
    }

    private static String dimensions(int width, int height) {
        return width > 0 && height > 0 ? width + " x " + height : "";
    }

    private static String duration(long durationMs) {
        if (durationMs <= 0L) return "";
        long seconds = (durationMs + 500L) / 1_000L;
        return String.format(Locale.US, "%d:%02d", seconds / 60L, seconds % 60L);
    }

    private static String displayCodec(Object value) {
        String codec = string(value).toLowerCase(Locale.US);
        if (codec.contains("avc") || codec.contains("h264")) return "H.264";
        if (codec.contains("hevc") || codec.contains("h265")) return "H.265";
        if (codec.contains("vp9")) return "VP9";
        if (codec.contains("vp8")) return "VP8";
        if (codec.contains("av01") || codec.contains("av1")) return "AV1";
        if (codec.contains("mp4v")) return "MPEG-4";
        return codec.length() == 0 ? "" : "Video";
    }

    private static Map<String,Object> unavailableStatus() {
        Map<String,Object> status = new LinkedHashMap<>();
        status.put("ok", false);
        status.put("active", false);
        status.put("photoConfigured", false);
        status.put("videoConfigured", false);
        status.put("mode", "naturalized");
        status.put("lastError", "unavailable");
        return status;
    }

    private interface ManagerOperation {
        Map<String,Object> run();
    }
}
