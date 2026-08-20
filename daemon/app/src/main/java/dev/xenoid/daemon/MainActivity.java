package dev.xenoid.daemon;

import android.app.Activity;
import android.content.ActivityNotFoundException;
import android.content.Intent;
import android.content.res.ColorStateList;
import android.graphics.Bitmap;
import android.graphics.Typeface;
import android.graphics.drawable.GradientDrawable;
import android.graphics.drawable.StateListDrawable;
import android.net.Uri;
import android.os.Build;
import android.os.Bundle;
import android.os.ParcelFileDescriptor;
import android.text.Editable;
import android.text.InputFilter;
import android.text.InputType;
import android.text.TextWatcher;
import android.text.method.PasswordTransformationMethod;
import android.view.Gravity;
import android.view.View;
import android.view.ViewGroup;
import android.view.Window;
import android.view.inputmethod.EditorInfo;
import android.widget.Button;
import android.widget.CheckBox;
import android.widget.CompoundButton;
import android.widget.EditText;
import android.widget.FrameLayout;
import android.widget.ImageView;
import android.widget.LinearLayout;
import android.widget.ProgressBar;
import android.widget.RadioButton;
import android.widget.RadioGroup;
import android.widget.ScrollView;
import android.widget.TextView;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.ByteArrayOutputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.OutputStream;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.Charset;
import java.nio.charset.CodingErrorAction;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.List;
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
    private static final int REQUEST_PROXY_SOURCE = 4103;
    private static final int PROXY_SOURCE_MAX_BYTES = 1_048_576;
    private static final int PROXY_RESPONSE_MAX_BYTES = 262_144;
    private static final int PROXY_TOKEN_MAX_BYTES = 4_096;
    private static final int PROXY_NODE_MAX_CHARS = 128;
    private static final String PROXY_DAEMON_BASE = "http://127.0.0.1:18765";
    private static final int PROXY_CONNECT_TIMEOUT_MS = 5_000;
    private static final int PROXY_STATUS_TIMEOUT_MS = 15_000;
    private static final int PROXY_MUTATION_TIMEOUT_MS = 20_000;
    private static final int PROXY_CHECK_TIMEOUT_MS = 30_000;
    private static final long PROXY_CHECK_INITIAL_DELAY_MS = 250L;
    private static final long PROXY_CHECK_MAX_DELAY_MS = 1_000L;
    private static final ExecutorService SETTINGS_WORKER =
            Executors.newSingleThreadExecutor(new ThreadFactory() {
                @Override public Thread newThread(Runnable runnable) {
                    Thread thread = new Thread(runnable, "xenoid-settings");
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

    private TextView proxyStatusText;
    private TextView proxyDetailText;
    private EditText proxySourceInput;
    private RadioButton proxyKindAuto;
    private RadioButton proxyKindEndpoint;
    private RadioButton proxyKindSubscription;
    private RadioButton proxyKindUriList;
    private RadioButton proxyKindClash;
    private CheckBox proxyUdpAllowed;
    private CheckBox proxyAllowInsecure;
    private CheckBox proxyEnabled;
    private EditText proxyNodeInput;
    private Button proxySaveSource;
    private Button proxyImportSource;
    private Button proxySelectNode;
    private Button proxyRefresh;
    private Button proxyCheck;
    private Button proxyClear;
    private boolean proxyConfiguredState;
    private boolean proxyUdpTouched;
    private boolean bindingProxyStatus;
    private String proxyOperationError;
    private final TextWatcher proxyFormWatcher = new TextWatcher() {
        @Override public void beforeTextChanged(CharSequence s, int start, int count, int after) { }
        @Override public void onTextChanged(CharSequence s, int start, int before, int count) { }
        @Override public void afterTextChanged(Editable editable) { updateProxyControls(); }
    };

    @Override protected void onCreate(Bundle savedInstanceState) {
        super.onCreate(savedInstanceState);
        requestDaemonService();

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

    @Override protected void onNewIntent(Intent intent) {
        super.onNewIntent(intent);
        setIntent(intent);
        requestDaemonService();
        if (intent != null && intent.getBooleanExtra(EXTRA_BOOTSTRAP, false)) {
            moveTaskToBack(true);
            finish();
        }
    }

    private void requestDaemonService() {
        startForegroundService(new Intent(this, XenoidDaemonService.class));
    }

    @Override protected void onResume() {
        super.onResume();
        if (!settingsMode) return;
        if (hasResumed && !busy) {
            if (mediaManager == null) initializeMediaManager();
            else refreshStatus("Refreshing camera status...");
            refreshProxyStatus("Refreshing proxy status...");
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
        if (requestCode == REQUEST_PROXY_SOURCE) {
            handleProxyImport(data.getData());
            return;
        }
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
        setTitle("Xenoid settings");
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

        TextView eyebrow = createText("XENOID SETTINGS", Ui.TYPE_CAPTION,
                Ui.COLOR_ACCENT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        eyebrow.setLetterSpacing(Ui.TRACKING_EYEBROW);
        content.addView(eyebrow);

        TextView title = createText("Xenoid settings", Ui.TYPE_TITLE,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams titleParams = wrap();
        titleParams.topMargin = dp(Ui.SPACE_2);
        content.addView(title, titleParams);
        markHeading(title);

        TextView intro = createText(
                "Manage the camera sources and the global proxy for this device. Source details stay private on this device.",
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

        TextView activationLabel = createText("CAMERA ACTIVATION", Ui.TYPE_CAPTION,
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

        addDivider(content);
        addProxySection(content);

        setContentView(scroll);
        refreshProxyStatus("Loading proxy status...");
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

    private void addProxySection(LinearLayout content) {
        TextView heading = createText("Global proxy", Ui.TYPE_SUBHEAD, Ui.COLOR_TEXT,
                Typeface.create("sans-serif-medium", Typeface.NORMAL));
        content.addView(heading);
        markHeading(heading);

        TextView description = createText(
                "Route this device's app traffic through one proxy source. Values you enter are sent only to the local daemon and are never shown again.",
                Ui.TYPE_BODY, Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        description.setLineSpacing(0f, Ui.LINE_HEIGHT_BODY);
        LinearLayout.LayoutParams descriptionParams = match();
        descriptionParams.topMargin = dp(Ui.SPACE_2);
        content.addView(description, descriptionParams);

        LinearLayout statusPanel = new LinearLayout(this);
        statusPanel.setOrientation(LinearLayout.VERTICAL);
        statusPanel.setPadding(dp(Ui.SPACE_4), dp(Ui.SPACE_3),
                dp(Ui.SPACE_4), dp(Ui.SPACE_3));
        statusPanel.setBackground(shape(Ui.COLOR_SURFACE, Ui.RADIUS_MEDIUM,
                Ui.COLOR_BORDER, Ui.HAIRLINE));
        LinearLayout.LayoutParams statusPanelParams = match();
        statusPanelParams.topMargin = dp(Ui.SPACE_3);
        content.addView(statusPanel, statusPanelParams);

        TextView statusLabel = createText("PROXY STATUS", Ui.TYPE_CAPTION,
                Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        statusLabel.setLetterSpacing(Ui.TRACKING_LABEL);
        statusPanel.addView(statusLabel);
        proxyStatusText = createText("Loading proxy status...", Ui.TYPE_BODY,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams proxyStatusParams = wrap();
        proxyStatusParams.topMargin = dp(Ui.SPACE_1);
        statusPanel.addView(proxyStatusText, proxyStatusParams);
        proxyDetailText = createText("", Ui.TYPE_BODY,
                Ui.COLOR_TEXT_MUTED, Typeface.create("sans-serif", Typeface.NORMAL));
        proxyDetailText.setLineSpacing(0f, Ui.LINE_HEIGHT_BODY);
        LinearLayout.LayoutParams proxyDetailParams = match();
        proxyDetailParams.topMargin = dp(Ui.SPACE_1);
        statusPanel.addView(proxyDetailText, proxyDetailParams);
        proxyDetailText.setVisibility(View.GONE);

        proxyEnabled = createCheckBox("Enable global proxy");
        LinearLayout.LayoutParams enableParams = match();
        enableParams.topMargin = dp(Ui.SPACE_3);
        content.addView(proxyEnabled, enableParams);
        proxyEnabled.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override public void onCheckedChanged(CompoundButton button, boolean isChecked) {
                if (bindingProxyStatus || busy) return;
                final boolean target = isChecked;
                runProxyOperation(target ? "Enabling proxy..." : "Disabling proxy...",
                        "The proxy state could not be changed. The previous state is unchanged.",
                        new ProxyOperation() {
                            @Override public Map<String,Object> run() {
                                return proxyRequest("POST", "/proxy/enabled",
                                        jsonBody("enabled", Boolean.valueOf(target)),
                                        PROXY_MUTATION_TIMEOUT_MS);
                            }
                        }, null);
            }
        });

        TextView sourceLabel = createText("Endpoint, subscription, or list", Ui.TYPE_BODY,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams sourceLabelParams = wrap();
        sourceLabelParams.topMargin = dp(Ui.SPACE_5);
        content.addView(sourceLabel, sourceLabelParams);

        proxySourceInput = createInputField(true, 0);
        proxySourceInput.setHint("Paste an endpoint URI, subscription link, or content");
        LinearLayout.LayoutParams sourceInputParams = match();
        sourceInputParams.topMargin = dp(Ui.SPACE_2);
        content.addView(proxySourceInput, sourceInputParams);
        sourceLabel.setLabelFor(proxySourceInput.getId());
        proxySourceInput.addTextChangedListener(proxyFormWatcher);

        TextView kindLabel = createText("Source type", Ui.TYPE_BODY,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams kindLabelParams = wrap();
        kindLabelParams.topMargin = dp(Ui.SPACE_4);
        content.addView(kindLabel, kindLabelParams);

        RadioGroup kindGroup = new RadioGroup(this);
        kindGroup.setOrientation(RadioGroup.VERTICAL);
        LinearLayout.LayoutParams kindGroupParams = match();
        kindGroupParams.topMargin = dp(Ui.SPACE_2);
        content.addView(kindGroup, kindGroupParams);
        proxyKindAuto = createModeButton(
                "Automatic\nDetect the type from the content");
        proxyKindEndpoint = createModeButton(
                "Endpoint\nOne direct HTTP or SOCKS5 proxy server URI");
        proxyKindSubscription = createModeButton(
                "Subscription\nLink to an online configuration, fetched by the proxy engine, never by this device");
        proxyKindUriList = createModeButton(
                "URI list\nOne proxy URI per line, or subscription content");
        proxyKindClash = createModeButton(
                "Clash configuration\nClash YAML or JSON with proxies");
        kindGroup.addView(proxyKindAuto, match());
        LinearLayout.LayoutParams kindEndpointParams = match();
        kindEndpointParams.topMargin = dp(Ui.SPACE_1);
        kindGroup.addView(proxyKindEndpoint, kindEndpointParams);
        LinearLayout.LayoutParams kindSubscriptionParams = match();
        kindSubscriptionParams.topMargin = dp(Ui.SPACE_1);
        kindGroup.addView(proxyKindSubscription, kindSubscriptionParams);
        LinearLayout.LayoutParams kindUriListParams = match();
        kindUriListParams.topMargin = dp(Ui.SPACE_1);
        kindGroup.addView(proxyKindUriList, kindUriListParams);
        LinearLayout.LayoutParams kindClashParams = match();
        kindClashParams.topMargin = dp(Ui.SPACE_1);
        kindGroup.addView(proxyKindClash, kindClashParams);
        proxyKindAuto.setChecked(true);

        proxyUdpAllowed = createCheckBox("Allow UDP when the source supports it");
        proxyUdpAllowed.setChecked(true);
        proxyUdpAllowed.setOnCheckedChangeListener(new CompoundButton.OnCheckedChangeListener() {
            @Override public void onCheckedChanged(CompoundButton button, boolean isChecked) {
                if (!bindingProxyStatus) proxyUdpTouched = true;
            }
        });
        LinearLayout.LayoutParams udpParams = match();
        udpParams.topMargin = dp(Ui.SPACE_3);
        content.addView(proxyUdpAllowed, udpParams);
        proxyAllowInsecure = createCheckBox("Allow plain HTTP sources (not recommended)");
        LinearLayout.LayoutParams insecureParams = match();
        insecureParams.topMargin = dp(Ui.SPACE_1);
        content.addView(proxyAllowInsecure, insecureParams);

        LinearLayout sourceActions = createControlRow();
        LinearLayout.LayoutParams sourceActionsParams = match();
        sourceActionsParams.topMargin = dp(Ui.SPACE_4);
        content.addView(sourceActions, sourceActionsParams);
        proxySaveSource = createButton("Save source", true);
        proxyImportSource = createButton("Import file", false);
        sourceActions.addView(proxySaveSource, weightedButton(false));
        sourceActions.addView(proxyImportSource, weightedButton(true));
        proxySaveSource.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { saveProxySource(); }
        });
        proxyImportSource.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { openProxyDocument(); }
        });

        TextView nodeLabel = createText("Selected node (optional)", Ui.TYPE_BODY,
                Ui.COLOR_TEXT, Typeface.create("sans-serif-medium", Typeface.NORMAL));
        LinearLayout.LayoutParams nodeLabelParams = wrap();
        nodeLabelParams.topMargin = dp(Ui.SPACE_4);
        content.addView(nodeLabel, nodeLabelParams);

        proxyNodeInput = createInputField(false, PROXY_NODE_MAX_CHARS);
        proxyNodeInput.setHint("Exact node name");
        LinearLayout.LayoutParams nodeInputParams = match();
        nodeInputParams.topMargin = dp(Ui.SPACE_2);
        content.addView(proxyNodeInput, nodeInputParams);
        nodeLabel.setLabelFor(proxyNodeInput.getId());
        proxyNodeInput.addTextChangedListener(proxyFormWatcher);

        LinearLayout nodeActions = createControlRow();
        LinearLayout.LayoutParams nodeActionsParams = match();
        nodeActionsParams.topMargin = dp(Ui.SPACE_3);
        content.addView(nodeActions, nodeActionsParams);
        proxySelectNode = createButton("Use this node", false);
        proxyRefresh = createButton("Refresh", false);
        nodeActions.addView(proxySelectNode, weightedButton(false));
        nodeActions.addView(proxyRefresh, weightedButton(true));
        proxySelectNode.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) { selectProxyNode(); }
        });
        proxyRefresh.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                refreshProxyStatus("Refreshing proxy status...");
            }
        });

        LinearLayout proxyActions = createControlRow();
        LinearLayout.LayoutParams proxyActionsParams = match();
        proxyActionsParams.topMargin = dp(Ui.SPACE_3);
        content.addView(proxyActions, proxyActionsParams);
        proxyCheck = createButton("Run check", false);
        proxyClear = createButton("Clear proxy", false);
        proxyActions.addView(proxyCheck, weightedButton(false));
        proxyActions.addView(proxyClear, weightedButton(true));
        proxyCheck.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                runProxyOperation("Checking the proxy data path...",
                        "The proxy check could not be completed.",
                        new ProxyOperation() {
                            @Override public Map<String,Object> run() {
                                return runProxyCheck();
                            }
                        }, null);
            }
        });
        proxyClear.setOnClickListener(new View.OnClickListener() {
            @Override public void onClick(View view) {
                runProxyOperation("Clearing proxy...",
                        "The proxy could not be cleared. The previous proxy state is unchanged.",
                        new ProxyOperation() {
                            @Override public Map<String,Object> run() {
                                return proxyRequest("POST", "/proxy/clear", "{}",
                                        PROXY_MUTATION_TIMEOUT_MS);
                            }
                        }, null);
            }
        });
    }

    private CheckBox createCheckBox(String label) {
        CheckBox box = new CheckBox(this);
        box.setText(label);
        box.setTextSize(Ui.TYPE_BODY);
        box.setTextColor(new ColorStateList(
                new int[][] {
                        new int[] { -Ui.STATE_ENABLED },
                        new int[] {}
                },
                new int[] { Ui.COLOR_DISABLED_TEXT, Ui.COLOR_TEXT }));
        box.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        box.setGravity(Gravity.CENTER_VERTICAL);
        box.setMinHeight(dp(Ui.CONTROL_HEIGHT));
        box.setPadding(dp(Ui.SPACE_2), dp(Ui.SPACE_1),
                dp(Ui.SPACE_2), dp(Ui.SPACE_1));
        box.setButtonTintList(new ColorStateList(
                new int[][] {
                        new int[] { Ui.STATE_CHECKED },
                        new int[] { -Ui.STATE_ENABLED },
                        new int[] {}
                },
                new int[] { Ui.COLOR_ACCENT, Ui.COLOR_DISABLED_TEXT, Ui.COLOR_TEXT_MUTED }));
        return box;
    }

    private EditText createInputField(boolean secret, int maxChars) {
        EditText field = new EditText(this);
        field.setId(View.generateViewId());
        field.setTextSize(Ui.TYPE_BODY);
        field.setTextColor(Ui.COLOR_TEXT);
        field.setHintTextColor(Ui.COLOR_TEXT_MUTED);
        field.setTypeface(Typeface.create("sans-serif", Typeface.NORMAL));
        field.setBackground(inputBackground());
        field.setPadding(dp(Ui.SPACE_3), dp(Ui.SPACE_2), dp(Ui.SPACE_3), dp(Ui.SPACE_2));
        field.setMinHeight(dp(Ui.CONTROL_HEIGHT));
        if (Build.VERSION.SDK_INT >= 26) {
            field.setImportantForAutofill(View.IMPORTANT_FOR_AUTOFILL_NO);
        }
        if (maxChars > 0) {
            field.setFilters(new InputFilter[] { new InputFilter.LengthFilter(maxChars) });
        }
        if (secret) {
            field.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_VARIATION_PASSWORD
                    | InputType.TYPE_TEXT_FLAG_MULTI_LINE
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            field.setTransformationMethod(PasswordTransformationMethod.getInstance());
            field.setGravity(Gravity.TOP | Gravity.START);
            field.setMinLines(2);
            field.setMaxLines(5);
            field.setVerticalScrollBarEnabled(true);
        } else {
            field.setInputType(InputType.TYPE_CLASS_TEXT
                    | InputType.TYPE_TEXT_FLAG_NO_SUGGESTIONS);
            field.setSingleLine(true);
            field.setImeOptions(EditorInfo.IME_ACTION_DONE);
        }
        return field;
    }

    private StateListDrawable inputBackground() {
        StateListDrawable states = new StateListDrawable();
        states.addState(new int[] { -Ui.STATE_ENABLED },
                shape(Ui.COLOR_DISABLED, Ui.RADIUS_SMALL,
                        Ui.COLOR_DISABLED, Ui.HAIRLINE));
        states.addState(new int[] { Ui.STATE_FOCUSED },
                shape(Ui.COLOR_SURFACE, Ui.RADIUS_SMALL,
                        Ui.COLOR_ACCENT, Ui.FOCUS_STROKE));
        states.addState(new int[] {},
                shape(Ui.COLOR_SURFACE, Ui.RADIUS_SMALL,
                        Ui.COLOR_BORDER, Ui.HAIRLINE));
        return states;
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

    private void openProxyDocument() {
        if (busy) return;
        Intent picker = new Intent(Intent.ACTION_OPEN_DOCUMENT);
        picker.addCategory(Intent.CATEGORY_OPENABLE);
        picker.addFlags(Intent.FLAG_GRANT_READ_URI_PERMISSION);
        picker.setType("*/*");
        try {
            startActivityForResult(picker, REQUEST_PROXY_SOURCE);
        } catch (ActivityNotFoundException ignored) {
            proxyOperationError = "No document picker is available.";
            renderProxyStatus(null);
        }
    }

    private void handleProxyImport(Uri uri) {
        if (busy || uri == null) return;
        final Uri selected = uri;
        final ProxyForm form = captureProxyForm();
        runProxyOperation("Importing proxy source...",
                "The source could not be imported. The previous proxy state is unchanged.",
                new ProxyOperation() {
                    @Override public Map<String,Object> run() {
                        return importProxySource(selected, form);
                    }
                }, new Runnable() {
                    @Override public void run() { proxyUdpTouched = false; }
                });
    }

    private void saveProxySource() {
        if (busy) return;
        final ProxyForm form = captureProxyForm();
        final String value = proxySourceInput.getText().toString();
        runProxyOperation("Saving proxy source...",
                "The source could not be saved. The previous proxy state is unchanged.",
                new ProxyOperation() {
                    @Override public Map<String,Object> run() {
                        return submitProxySource(form, value);
                    }
                }, new Runnable() {
                    @Override public void run() {
                        proxySourceInput.setText("");
                        proxyUdpTouched = false;
                    }
                });
    }

    private void selectProxyNode() {
        if (busy) return;
        final String name = proxyNodeInput.getText().toString().trim();
        if (name.length() == 0) return;
        runProxyOperation("Selecting node...",
                "The node could not be selected. The previous selection is unchanged.",
                new ProxyOperation() {
                    @Override public Map<String,Object> run() {
                        return proxyRequest("POST", "/proxy/select",
                                jsonBody("name", name), PROXY_MUTATION_TIMEOUT_MS);
                    }
                }, null);
    }

    private Map<String,Object> runProxyCheck() {
        Map<String,Object> started = proxyRequest("POST", "/proxy/check", "{}",
                PROXY_MUTATION_TIMEOUT_MS);
        if (started == null || !flag(started, "ok")) {
            return started == null ? proxyLocalError("unavailable") : started;
        }
        Map<String,Object> baseline = proxyRequest("GET", "/proxy/status", null,
                PROXY_STATUS_TIMEOUT_MS);
        if (baseline == null || !flag(baseline, "ok")) return proxyLocalError("unavailable");
        String epoch = string(baseline.get("runtimeEpoch"));
        long generation = positiveLong(baseline.get("generation"));
        long checkId = positiveLong(baseline.get("checkId"));
        if (checkId <= 0L) return proxyLocalError("unavailable");
        long deadline = System.nanoTime() + PROXY_CHECK_TIMEOUT_MS * 1_000_000L;
        long delayMs = PROXY_CHECK_INITIAL_DELAY_MS;
        while (System.nanoTime() < deadline) {
            try {
                Thread.sleep(delayMs);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                return proxyLocalError("unavailable");
            }
            delayMs = Math.min(PROXY_CHECK_MAX_DELAY_MS, delayMs * 2L);
            Map<String,Object> status;
            try {
                status = proxyRequest("GET", "/proxy/status", null, PROXY_STATUS_TIMEOUT_MS);
            } catch (Throwable ignored) {
                continue;
            }
            if (status == null || !flag(status, "ok")) continue;
            if (!epoch.equals(string(status.get("runtimeEpoch")))) {
                return proxyLocalError("runtime_epoch_mismatch");
            }
            if (positiveLong(status.get("generation")) != generation) continue;
            if (positiveLong(status.get("checkId")) != checkId) continue;
            boolean udpAllowed = flag(status, "udpAllowed");
            Object report = status.get("report");
            Map<?,?> reportMap = report instanceof Map ? (Map<?,?>) report : null;
            boolean reportMatches = reportMap != null
                    && positiveLong(reportMap.get("generation")) == generation
                    && positiveLong(reportMap.get("checkId")) == checkId;
            if (reportMatches) {
                String reportError = string(reportMap.get("errorCode"));
                if (reportError.length() > 0) return proxyLocalError(reportError);
            }
            Object probe = status.get("probe");
            Map<?,?> probeMap = probe instanceof Map ? (Map<?,?>) probe : null;
            boolean probeMatches = probeMap != null
                    && positiveLong(probeMap.get("checkId")) == checkId;
            if (probeMatches) {
                String probeError = string(probeMap.get("errorCode"));
                if (probeError.length() > 0) return proxyLocalError(probeError);
            }
            boolean verified = reportMatches
                    && Boolean.TRUE.equals(reportMap.get("structuralApplied"))
                    && Boolean.TRUE.equals(reportMap.get("dataPlaneVerified"))
                    && proxyCapabilityMatrixReady(reportMap.get("capabilities"), udpAllowed)
                    && "active".equals(string(reportMap.get("phase")));
            boolean probeOk = probeMatches
                    && proxyCapabilityMatrixReady(probeMap.get("capabilities"), udpAllowed)
                    && string(probeMap.get("errorCode")).length() == 0;
            if (verified && probeOk) return started;
        }
        return proxyLocalError("data_plane_unverified");
    }

    private ProxyForm captureProxyForm() {
        ProxyForm form = new ProxyForm();
        if (proxyKindEndpoint.isChecked()) form.explicitKind = "endpoint";
        else if (proxyKindSubscription.isChecked()) form.explicitKind = "subscription";
        else if (proxyKindUriList.isChecked()) form.explicitKind = "uri_list";
        else if (proxyKindClash.isChecked()) form.explicitKind = "clash";
        form.enable = proxyEnabled.isChecked();
        form.node = proxyNodeInput.getText().toString().trim();
        form.udpAllowed = proxyUdpAllowed.isChecked();
        form.allowInsecureHttp = proxyAllowInsecure.isChecked();
        return form;
    }

    private boolean runProxyOperation(String progressLabel, final String failureMessage,
                                      final ProxyOperation operation,
                                      final Runnable onSuccess) {
        if (destroyed) return false;
        setBusy(true, progressLabel);
        try {
            SETTINGS_WORKER.execute(new Runnable() {
                @Override public void run() {
                    Map<String,Object> result;
                    try {
                        result = operation.run();
                    } catch (Throwable ignored) {
                        result = null;
                    }
                    final boolean succeeded = result != null && flag(result, "ok");
                    final String errorCode =
                            result == null ? "unavailable" : string(result.get("error"));
                    Map<String,Object> status;
                    try {
                        status = proxyRequest("GET", "/proxy/status", null,
                                PROXY_STATUS_TIMEOUT_MS);
                    } catch (Throwable ignored) {
                        status = null;
                    }
                    final Map<String,Object> finishedStatus = status;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            if (destroyed) return;
                            proxyOperationError = succeeded
                                    ? null : proxyFailureText(errorCode, failureMessage);
                            renderProxyStatus(finishedStatus);
                            setBusy(false, null);
                            if (succeeded) {
                                if (onSuccess != null) onSuccess.run();
                            } else if (proxyStatusText != null && proxyOperationError != null) {
                                proxyStatusText.announceForAccessibility(proxyOperationError);
                            }
                        }
                    });
                }
            });
            return true;
        } catch (RuntimeException ignored) {
            proxyOperationError = failureMessage;
            renderProxyStatus(null);
            setBusy(false, null);
            return false;
        }
    }

    private void refreshProxyStatus(String progressLabel) {
        if (destroyed) return;
        setBusy(true, progressLabel);
        try {
            SETTINGS_WORKER.execute(new Runnable() {
                @Override public void run() {
                    Map<String,Object> status;
                    try {
                        status = proxyRequest("GET", "/proxy/status", null,
                                PROXY_STATUS_TIMEOUT_MS);
                    } catch (Throwable ignored) {
                        status = null;
                    }
                    final Map<String,Object> finished = status;
                    runOnUiThread(new Runnable() {
                        @Override public void run() {
                            if (destroyed) return;
                            renderProxyStatus(finished);
                            setBusy(false, null);
                        }
                    });
                }
            });
        } catch (RuntimeException ignored) {
            setBusy(false, null);
        }
    }

    private void renderProxyStatus(Map<String,Object> status) {
        if (proxyStatusText == null) return;
        boolean ok = status != null && flag(status, "ok");
        boolean configured = ok && flag(status, "configured");
        boolean enabled = ok && flag(status, "enabled");
        boolean udpAllowed = ok && flag(status, "udpAllowed");
        boolean allowInsecure = ok && flag(status, "allowInsecureHttp");
        boolean quarantined = ok && flag(status, "quarantined");
        String kind = ok ? string(status.get("sourceKind")) : "";
        long generation = ok ? positiveLong(status.get("generation")) : 0L;
        long checkId = ok ? positiveLong(status.get("checkId")) : 0L;
        String runtimeEpoch = ok ? string(status.get("runtimeEpoch")) : "";
        String node = ok
                ? sanitizeProxyNodeDisplay(string(status.get("selectedNode"))) : "";
        boolean structural = false;
        boolean verified = false;
        String phase = "";
        Object report = ok ? status.get("report") : null;
        if (report instanceof Map) {
            Map<?,?> reportMap = (Map<?,?>) report;
            structural = Boolean.TRUE.equals(reportMap.get("structuralApplied"));
            verified = Boolean.TRUE.equals(reportMap.get("dataPlaneVerified"));
            String reportedPhase = reportMap.get("phase") instanceof String
                    ? (String) reportMap.get("phase") : "";
            if ("active".equals(reportedPhase) || "off".equals(reportedPhase)
                    || "quarantined".equals(reportedPhase) || "staging".equals(reportedPhase)
                    || "applying".equals(reportedPhase)) {
                phase = reportedPhase;
            }
        }
        Object probe = ok ? status.get("probe") : null;
        boolean phaseActive = "active".equals(phase);
        boolean phaseOff = "off".equals(phase);
        boolean phaseQuarantine = "quarantined".equals(phase);
        boolean phaseStaging = "staging".equals(phase) || "applying".equals(phase);

        String headline;
        int color;
        if (proxyOperationError != null) {
            headline = proxyOperationError;
            color = Ui.COLOR_ERROR;
        } else if (!ok) {
            headline = "Proxy status is unavailable. The daemon may still be starting.";
            color = Ui.COLOR_TEXT_MUTED;
        } else if (!configured) {
            headline = "No proxy source. Traffic uses the direct connection.";
            color = Ui.COLOR_TEXT_MUTED;
        } else if (enabled && phaseActive && structural && verified) {
            headline = generation > 0L
                    ? "Ready - data path verified for generation " + generation + "."
                    : "Ready - proxy data path verified.";
            color = Ui.COLOR_SUCCESS;
        } else if (!enabled && phaseOff && structural && verified) {
            headline = "Off - direct connection verified.";
            color = Ui.COLOR_TEXT_MUTED;
        } else if (quarantined || phaseQuarantine) {
            headline = "Quarantined - traffic is blocked until the proxy engine is ready.";
            color = Ui.COLOR_ACCENT;
        } else if (enabled && (phaseStaging || phaseActive)) {
            headline = "Applying - proxy verification is pending.";
            color = Ui.COLOR_ACCENT;
        } else if (!enabled && (phaseStaging || phaseActive)) {
            headline = "Turning off - proxy state is being removed.";
            color = Ui.COLOR_TEXT_MUTED;
        } else if (!enabled) {
            headline = "Configured - proxy is off.";
            color = Ui.COLOR_TEXT_MUTED;
        } else {
            headline = "Pending - waiting for the proxy engine.";
            color = Ui.COLOR_TEXT_MUTED;
        }
        proxyStatusText.setText(headline);
        proxyStatusText.setTextColor(color);

        if (ok && configured) {
            StringBuilder detail = new StringBuilder();
            appendDetail(detail, "endpoint".equals(kind) ? "Endpoint"
                    : "subscription".equals(kind) ? "Subscription link"
                    : "uri_list".equals(kind) ? "URI list"
                    : "clash".equals(kind) ? "Clash configuration" : "");
            appendDetail(detail, node.length() > 0 ? "Node: " + node : "");
            appendDetail(detail, udpAllowed ? "UDP: allowed" : "UDP: blocked");
            if (allowInsecure) appendDetail(detail, "Plain HTTP: allowed");
            if (generation > 0L) appendDetail(detail, "Generation " + generation);
            if (checkId > 0L) appendDetail(detail, "Check " + checkId);
            proxyDetailText.setText(detail.toString());
            proxyDetailText.setVisibility(detail.length() > 0 ? View.VISIBLE : View.GONE);
        } else {
            proxyDetailText.setText("");
            proxyDetailText.setVisibility(View.GONE);
        }

        if (ok) {
            proxyConfiguredState = configured;
            bindingProxyStatus = true;
            if (!proxyEnabled.hasFocus()) proxyEnabled.setChecked(enabled);
            if (!proxyUdpTouched && !proxyUdpAllowed.hasFocus()) {
                proxyUdpAllowed.setChecked(configured ? udpAllowed : true);
            }
            if (!proxyAllowInsecure.hasFocus()) proxyAllowInsecure.setChecked(allowInsecure);
            if (!proxyNodeInput.hasFocus()
                    && !proxyNodeInput.getText().toString().equals(node)) {
                proxyNodeInput.setText(node);
            }
            bindingProxyStatus = false;
        }
        updateControls();
    }

    private void updateProxyControls() {
        if (proxyStatusText == null) return;
        boolean idle = !busy;
        boolean hasSource = proxySourceInput.getText().toString().trim().length() > 0;
        boolean hasNode = proxyNodeInput.getText().toString().trim().length() > 0;
        proxySaveSource.setEnabled(idle && hasSource);
        proxyImportSource.setEnabled(idle);
        proxySelectNode.setEnabled(idle && hasNode);
        proxyRefresh.setEnabled(idle);
        proxyCheck.setEnabled(idle && proxyConfiguredState && proxyEnabled.isChecked());
        proxyClear.setEnabled(idle && proxyConfiguredState);
        proxyEnabled.setEnabled(idle && proxyConfiguredState);
        proxySourceInput.setEnabled(idle);
        proxyNodeInput.setEnabled(idle);
        proxyUdpAllowed.setEnabled(idle);
        proxyAllowInsecure.setEnabled(idle);
        proxyKindAuto.setEnabled(idle);
        proxyKindEndpoint.setEnabled(idle);
        proxyKindSubscription.setEnabled(idle);
        proxyKindUriList.setEnabled(idle);
        proxyKindClash.setEnabled(idle);
    }

    private Map<String,Object> submitProxySource(ProxyForm form, String value) {
        String trimmed = value == null ? "" : value.trim();
        if (trimmed.length() == 0) return proxyLocalError("source_empty");
        byte[] utf8;
        try {
            utf8 = trimmed.getBytes("UTF-8");
        } catch (Throwable ignored) {
            return proxyLocalError("invalid_text");
        }
        if (utf8.length > PROXY_SOURCE_MAX_BYTES) return proxyLocalError("source_too_large");
        String kind = form.explicitKind != null ? form.explicitKind : inferProxyKind(trimmed);
        Map<String,Object> payload = new LinkedHashMap<>();
        payload.put("kind", kind);
        payload.put("value", trimmed);
        payload.put("enable", Boolean.valueOf(form.enable));
        payload.put("selectedNode", form.node);
        payload.put("udpAllowed", Boolean.valueOf(form.udpAllowed));
        payload.put("allowInsecureHttp", Boolean.valueOf(form.allowInsecureHttp));
        String body;
        try {
            body = new JSONObject(payload).toString();
        } catch (Throwable ignored) {
            return proxyLocalError("invalid_request");
        }
        return proxyRequest("POST", "/proxy/source", body, PROXY_MUTATION_TIMEOUT_MS);
    }

    private Map<String,Object> importProxySource(Uri uri, ProxyForm form) {
        ParcelFileDescriptor descriptor = null;
        try {
            descriptor = getContentResolver().openFileDescriptor(uri, "r");
            if (descriptor == null) return proxyLocalError("read_failed");
            long size = descriptor.getStatSize();
            if (size > PROXY_SOURCE_MAX_BYTES) return proxyLocalError("source_too_large");
            InputStream input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
            descriptor = null;
            ByteArrayOutputStream buffer = new ByteArrayOutputStream();
            byte[] chunk = new byte[16384];
            int total = 0;
            int read;
            boolean oversized = false;
            while ((read = input.read(chunk)) >= 0) {
                total += read;
                if (total > PROXY_SOURCE_MAX_BYTES) {
                    oversized = true;
                    break;
                }
                buffer.write(chunk, 0, read);
            }
            try { input.close(); } catch (Throwable ignored) { }
            if (oversized) return proxyLocalError("source_too_large");
            java.nio.charset.CharsetDecoder decoder = Charset.forName("UTF-8").newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT);
            String text = decoder.decode(ByteBuffer.wrap(buffer.toByteArray())).toString();
            return submitProxySource(form, text);
        } catch (CharacterCodingException invalid) {
            return proxyLocalError("invalid_text");
        } catch (Throwable ignored) {
            return proxyLocalError("read_failed");
        } finally {
            closeDescriptor(descriptor);
        }
    }

    private Map<String,Object> proxyRequest(
            String method, String path, String body, int readTimeoutMs) {
        HttpURLConnection connection = null;
        try {
            String token = readDaemonToken();
            if (token.length() == 0) return proxyLocalError("unavailable");
            connection = (HttpURLConnection) new URL(PROXY_DAEMON_BASE + path).openConnection();
            connection.setConnectTimeout(PROXY_CONNECT_TIMEOUT_MS);
            connection.setReadTimeout(readTimeoutMs);
            connection.setUseCaches(false);
            connection.setInstanceFollowRedirects(false);
            connection.setRequestMethod(method);
            connection.setRequestProperty("X-Xenoid-Token", token);
            connection.setRequestProperty("Accept", "application/json");
            if (body != null) {
                byte[] bytes = body.getBytes("UTF-8");
                connection.setDoOutput(true);
                connection.setRequestProperty("Content-Type", "application/json");
                connection.setFixedLengthStreamingMode(bytes.length);
                OutputStream output = connection.getOutputStream();
                try {
                    output.write(bytes);
                    output.flush();
                } finally {
                    try { output.close(); } catch (Throwable ignored) { }
                }
            }
            int code = connection.getResponseCode();
            InputStream stream;
            try {
                stream = code >= 400 ? connection.getErrorStream() : connection.getInputStream();
            } catch (Throwable ignored) {
                stream = null;
            }
            String responseBody =
                    stream == null ? "" : readBoundedUtf8(stream, PROXY_RESPONSE_MAX_BYTES);
            if (code == 401) return proxyLocalError("unauthorized");
            Map<String,Object> parsed = parseJsonObject(responseBody);
            if (parsed == null) {
                return proxyLocalError(code >= 400 ? "unavailable" : "invalid_response");
            }
            return parsed;
        } catch (Throwable ignored) {
            return proxyLocalError("unavailable");
        } finally {
            if (connection != null) connection.disconnect();
        }
    }

    private String readDaemonToken() {
        InputStream input = null;
        try {
            File file = new File(getFilesDir(), "daemon.token");
            if (!file.isFile()) return "";
            long length = file.length();
            if (length <= 0L || length > PROXY_TOKEN_MAX_BYTES) return "";
            input = new FileInputStream(file);
            return readBoundedUtf8(input, PROXY_TOKEN_MAX_BYTES).trim();
        } catch (Throwable ignored) {
            return "";
        } finally {
            if (input != null) {
                try { input.close(); } catch (Throwable ignored) { }
            }
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
        updateProxyControls();
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

    private static boolean proxyCapabilityMatrixReady(Object value, boolean udpAllowed) {
        if (!(value instanceof Map)) return false;
        Map<?,?> capabilities = (Map<?,?>) value;
        String[] names = {
                "v4DnsProxy", "v4TcpProxy", "v4UdpProxy",
                "v6DnsProxy", "v6TcpProxy", "v6UdpProxy"
        };
        if (capabilities.size() != names.length) return false;
        for (String name : names) {
            boolean expected = udpAllowed || !name.contains("Udp");
            if (!Boolean.valueOf(expected).equals(capabilities.get(name))) return false;
        }
        return true;
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

    private static Map<String,Object> proxyLocalError(String code) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("ok", Boolean.FALSE);
        result.put("error", code);
        return result;
    }

    private static String jsonBody(String key, Object value) {
        try {
            JSONObject object = new JSONObject();
            object.put(key, value);
            return object.toString();
        } catch (Throwable ignored) {
            return "{}";
        }
    }

    private static String readBoundedUtf8(InputStream stream, int maxBytes) throws Exception {
        ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        byte[] chunk = new byte[8192];
        int total = 0;
        int read;
        while ((read = stream.read(chunk)) >= 0) {
            total += read;
            if (total > maxBytes) throw new java.io.IOException("bounded read exceeded");
            buffer.write(chunk, 0, read);
        }
        return new String(buffer.toByteArray(), "UTF-8");
    }

    private static Map<String,Object> parseJsonObject(String body) {
        if (body == null || body.length() == 0) return null;
        try {
            Object value = new JSONTokener(body).nextValue();
            if (!(value instanceof JSONObject)) return null;
            return jsonObjectToMap((JSONObject) value);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static Map<String,Object> jsonObjectToMap(JSONObject object) throws Exception {
        Map<String,Object> map = new LinkedHashMap<>();
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            String key = keys.next();
            map.put(key, jsonValue(object.get(key)));
        }
        return map;
    }

    private static Object jsonValue(Object value) throws Exception {
        if (value == null || value == JSONObject.NULL) return null;
        if (value instanceof JSONObject) return jsonObjectToMap((JSONObject) value);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value;
            List<Object> list = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) list.add(jsonValue(array.get(i)));
            return list;
        }
        return value;
    }

    private static String inferProxyKind(String value) {
        String trimmed = value.trim();
        String lower = trimmed.toLowerCase(Locale.US);
        if (lower.indexOf('\n') < 0
                && (lower.startsWith("http://") || lower.startsWith("https://")
                || lower.startsWith("socks5://") || lower.startsWith("socks5h://"))) {
            return "endpoint";
        }
        if (trimmed.startsWith("{") || trimmed.startsWith("---")
                || startsLineWith(lower, "proxies:")
                || startsLineWith(lower, "proxy-providers:")) {
            return "clash";
        }
        return "uri_list";
    }

    private static boolean startsLineWith(String text, String prefix) {
        int from = 0;
        while (from < text.length()) {
            int end = text.indexOf('\n', from);
            if (end < 0) end = text.length();
            int start = from;
            while (start < end && text.charAt(start) == ' ') start++;
            if (text.regionMatches(start, prefix, 0, prefix.length())) return true;
            from = end + 1;
        }
        return false;
    }

    private static String sanitizeDisplay(String value, int maxChars) {
        if (value == null) return "";
        StringBuilder out = new StringBuilder(value.length());
        for (int i = 0; i < value.length() && out.length() < maxChars; i++) {
            char c = value.charAt(i);
            out.append(Character.isISOControl(c) ? ' ' : c);
        }
        return out.toString().trim();
    }

    private static String sanitizeProxyNodeDisplay(String value) {
        String clean = sanitizeDisplay(value, PROXY_NODE_MAX_CHARS);
        int scheme = clean.indexOf("://");
        if (scheme > 0) {
            return clean.substring(0, scheme + 3) + "<redacted>";
        }
        int query = clean.indexOf('?');
        int fragment = clean.indexOf('#');
        int suffix = query < 0 ? fragment
                : (fragment < 0 ? query : Math.min(query, fragment));
        if (suffix >= 0) {
            clean = clean.substring(0, suffix) + "?<redacted>";
        }
        int at = clean.indexOf('@');
        if (at >= 0) {
            clean = "<redacted>@" + clean.substring(at + 1);
        }
        return clean;
    }

    private static void appendDetail(StringBuilder builder, String part) {
        if (part == null || part.length() == 0) return;
        if (builder.length() > 0) builder.append("  ·  ");
        builder.append(part);
    }

    private static String proxyFailureText(String code, String fallback) {
        if ("unauthorized".equals(code)) {
            return "Proxy control was not authorized. Restart the app and try again.";
        }
        if ("unavailable".equals(code)) {
            return "The daemon did not respond. Try again in a moment.";
        }
        if ("invalid_request".equals(code) || "invalid_response".equals(code)) {
            return "The proxy request was rejected. No changes were made.";
        }
        if ("source_empty".equals(code)) {
            return "Enter or import a source first.";
        }
        if ("source_too_large".equals(code)) {
            return "The source is larger than the 1 MiB limit. No changes were made.";
        }
        if ("read_failed".equals(code)) {
            return "The selected file could not be read. No changes were made.";
        }
        if ("invalid_text".equals(code)) {
            return "The selected file is not UTF-8 text. No changes were made.";
        }
        if ("source_invalid".equals(code)) {
            return "The source was rejected. Check the content and source type, then try again.";
        }
        if ("source_fetch_denied".equals(code)) {
            return "The source address is not allowed. No changes were made.";
        }
        if ("provider_empty".equals(code)) {
            return "The source has no usable proxy nodes. No changes were made.";
        }
        if ("selection_missing".equals(code)) {
            return "That node is not in the current source. Check the exact name.";
        }
        if ("upstream_unreachable".equals(code)) {
            return "The selected node is unreachable right now.";
        }
        if ("engine_download_failed".equals(code) || "tproxy_unsupported".equals(code)) {
            return "The proxy engine is not available on this device.";
        }
        if ("agent_stale".equals(code) || "runtime_epoch_mismatch".equals(code)
                || "data_plane_unverified".equals(code) || "agent_unavailable".equals(code)) {
            return "The proxy engine is not ready yet. Wait a moment, then try Refresh.";
        }
        return fallback;
    }

    private static final class ProxyForm {
        String explicitKind;
        boolean enable;
        String node = "";
        boolean udpAllowed;
        boolean allowInsecureHttp;
    }

    private interface ProxyOperation {
        Map<String,Object> run();
    }

    private interface ManagerOperation {
        Map<String,Object> run();
    }
}
