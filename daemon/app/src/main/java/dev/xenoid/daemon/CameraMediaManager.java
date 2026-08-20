package dev.xenoid.daemon;

import android.content.Context;
import android.graphics.Bitmap;
import android.graphics.BitmapFactory;
import android.graphics.ImageDecoder;
import android.graphics.ImageFormat;
import android.media.Image;
import android.media.ImageReader;
import android.media.MediaCodec;
import android.media.MediaExtractor;
import android.media.MediaFormat;
import android.media.MediaMetadataRetriever;
import android.os.ParcelFileDescriptor;
import android.os.Process;
import android.os.SystemClock;
import android.system.Os;
import android.system.OsConstants;

import org.json.JSONObject;

import java.io.File;
import java.io.FileDescriptor;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.file.AtomicMoveNotSupportedException;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Iterator;
import java.util.LinkedHashMap;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.Callable;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;

/** Serialized owner of accepted camera media and its root-owned active projection. */
public final class CameraMediaManager {
    private static final long MAX_PHOTO_INPUT_BYTES = 64L * 1024L * 1024L;
    private static final long MAX_PHOTO_PNG_BYTES = 64L * 1024L * 1024L;
    private static final long MAX_VIDEO_BYTES = 2L * 1024L * 1024L * 1024L;
    private static final long MAX_VIDEO_DURATION_US = 24L * 60L * 60L * 1000000L;
    private static final long MAX_PIXELS = 64L * 1024L * 1024L;
    private static final int MAX_DIMENSION = 8192;
    private static final long VIDEO_DECODE_TIMEOUT_MS = 20000L;
    private static final int COLOR_METADATA_UNSPECIFIED = 0;
    private static final int COLOR_TRANSFER_SRGB = 2;
    private static final String DEFAULT_MODE = "naturalized";
    private static final String STATE_NAME = "state.json";
    private static final long RECONCILIATION_RETRY_DELAY_MS = 5000L;
    private static final long DOCUMENT_COPY_TIMEOUT_MS = 10L * 60L * 1000L;

    private static CameraMediaManager instance;

    private final Context context;
    private final File directory;
    private final File stateFile;
    private final ExecutorService publicationExecutor =
            Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "camera-publication");
                thread.setDaemon(true);
                return thread;
            });
    private final ExecutorService documentCopyExecutor =
            Executors.newCachedThreadPool(runnable -> {
                Thread thread = new Thread(runnable, "camera-document-copy");
                thread.setDaemon(true);
                return thread;
            });
    private State state;
    private String lastError = "";
    private boolean stateAvailable;
    private boolean publicationReady;
    private Future<PublicationResult> reconciliationFuture;
    private long reconciliationRetryAtMs;
    private long publicationEpoch;
    private final Set<String> pendingImports = new HashSet<>();

    public static synchronized CameraMediaManager get(Context context) {
        if (instance == null) {
            instance = new CameraMediaManager(context.getApplicationContext());
        }
        return instance;
    }

    private CameraMediaManager(Context context) {
        this.context = context;
        this.directory = new File(context.getFilesDir(), "camera-media");
        this.stateFile = new File(directory, STATE_NAME);
        State initial = State.empty();
        try {
            boolean created = false;
            if (!directory.exists()) {
                if (!directory.mkdirs()) throw new ValidationFailure("state unavailable");
                created = true;
            }
            if (!directory.isDirectory() || Files.isSymbolicLink(directory.toPath())
                    || Os.lstat(directory.getAbsolutePath()).st_uid != Process.myUid()) {
                throw new ValidationFailure("state unavailable");
            }
            Os.chmod(directory.getAbsolutePath(), 0700);
            if (created) syncDirectory(directory.getParentFile());
        } catch (Throwable ignored) {
            state = initial;
            stateAvailable = false;
            lastError = "state unavailable";
            return;
        }

        boolean recovered = false;
        try {
            initial = loadState();
            validatePersistedStateSources(initial);
        } catch (InvalidPersistedState invalidState) {
            initial = State.empty();
            try {
                commitState(initial);
                recovered = true;
            } catch (Throwable recoveryFailure) {
                state = initial;
                stateAvailable = false;
                lastError = "state unavailable";
                return;
            }
        } catch (Throwable unavailableState) {
            state = State.empty();
            stateAvailable = false;
            lastError = "state unavailable";
            return;
        }

        state = initial;
        stateAvailable = true;
        boolean cleanupReady = cleanupLocalFiles();
        publicationReady = false;
        if (!cleanupReady && !recovered) {
            stateAvailable = false;
            lastError = "state unavailable";
        } else {
            lastError = cleanupReady ? "activation reconciliation pending"
                    : "orphan cleanup pending";
        }
    }

    public synchronized Map<String,Object> status() {
        try {
            refreshReconciliationLocked();
            return statusLocked(stateAvailable && publicationReady);
        } catch (Throwable ignored) {
            return minimalFailure("status unavailable");
        }
    }

    synchronized boolean healthReady() {
        return stateAvailable && publicationReady;
    }

    synchronized BootstrapCoordinator.ComponentStatus reconcileBootstrap(
            long deadline, BootstrapCoordinator.CancellationSignal cancellation) {
        if (!stateAvailable) {
            return BootstrapCoordinator.ComponentStatus.failed(
                    "camera_state_unavailable", bootstrapFields());
        }
        if (cancellation.isCancelled()) {
            return BootstrapCoordinator.ComponentStatus.cancelled();
        }
        long remaining = deadline - SystemClock.elapsedRealtime();
        if (remaining <= 0) return BootstrapCoordinator.ComponentStatus.timedOut();

        final State expectedState = state;
        final long expectedEpoch = ++publicationEpoch;
        final RootHelper.ConnectionHandle connection = cancellation.currentHandle();
        if (connection == null) {
            return BootstrapCoordinator.ComponentStatus.failed(
                    "camera_publication_unavailable", bootstrapFields());
        }
        Future<PublicationResult> future = publicationExecutor.submit(() -> {
            boolean ready;
            try (RootHelper.ConnectionScope ignored =
                         RootHelper.bindConnectionHandle(connection)) {
                ready = reconcilePublicationNow(expectedState);
            } catch (Throwable ignored) {
                ready = false;
            }
            return new PublicationResult(expectedState, expectedEpoch, ready);
        });
        reconciliationFuture = future;
        try {
            PublicationResult result = future.get(remaining, TimeUnit.MILLISECONDS);
            reconciliationFuture = null;
            if (result.state != state || result.epoch != publicationEpoch) {
                publicationReady = false;
                lastError = "activation reconciliation pending";
                return BootstrapCoordinator.ComponentStatus.failed(
                        "camera_state_changed", bootstrapFields());
            }
            publicationReady = result.ready;
            lastError = result.ready ? "" : "activation reconciliation pending";
            if (cancellation.isCancelled()) {
                return BootstrapCoordinator.ComponentStatus.cancelled();
            }
            if (SystemClock.elapsedRealtime() > deadline) {
                return BootstrapCoordinator.ComponentStatus.timedOut();
            }
            if (!publicationReady) {
                return BootstrapCoordinator.ComponentStatus.failed(
                        "camera_publication_unavailable", bootstrapFields());
            }
            return BootstrapCoordinator.ComponentStatus.ready(
                    configuredForBootstrap() ? "ready" : "unconfigured",
                    bootstrapFields());
        } catch (TimeoutException timeout) {
            future.cancel(true);
            RootHelper.ConnectionHandle handle = cancellation.currentHandle();
            if (handle != null) handle.cancel();
            reconciliationFuture = null;
            publicationReady = false;
            lastError = "activation reconciliation pending";
            return BootstrapCoordinator.ComponentStatus.timedOut();
        } catch (InterruptedException interrupted) {
            future.cancel(true);
            Thread.currentThread().interrupt();
            return BootstrapCoordinator.ComponentStatus.cancelled();
        } catch (ExecutionException failed) {
            future.cancel(true);
            reconciliationFuture = null;
            publicationReady = false;
            lastError = "activation reconciliation pending";
            return BootstrapCoordinator.ComponentStatus.failed(
                    "camera_publication_unavailable", bootstrapFields());
        }
    }

    private boolean configuredForBootstrap() {
        return state.photo != null || state.video != null;
    }

    private Map<String, Object> bootstrapFields() {
        return XenoidDaemonService.map(
                "configured", configuredForBootstrap(),
                "generation", state.generation,
                "active", state.active && publicationReady,
                "publicationReady", publicationReady);
    }

    public synchronized Map<String,Object> importStaged(
            String kind, String stagingPath, long size, String sha256) {
        boolean safeStage = isStagePath(stagingPath);
        File raw = null;
        File accepted = null;
        try {
            validateKind(kind);
            ensureStateAvailable();
            if (!safeStage || sha256 == null || !sha256.matches("[0-9a-f]{64}")) {
                throw new ValidationFailure("invalid staging metadata");
            }
            validateDeclaredSize(kind, size);
            raw = newPrivateFile("incoming-", ".tmp");
            if (!RootHelper.copyCameraStage(stagingPath, raw, size, sha256, Process.myUid())) {
                throw new ValidationFailure("source transfer failed");
            }
            verifyPrivateFile(raw, size, sha256);
            accepted = "photo".equals(kind)
                    ? newPrivateFile("photo-", ".png")
                    : newPrivateFile("video-", ".bin");
            ValidatedSource source = validateCandidate(kind, raw, accepted);
            State next = withSource(state, kind, source);
            Map<String,Object> result = commitMutation(next);
            if (!isRetainedSource(accepted)) deleteQuietly(accepted);
            return result;
        } catch (ValidationFailure e) {
            deleteQuietly(accepted);
            return fail(e.safeMessage);
        } catch (Throwable ignored) {
            deleteQuietly(accepted);
            return fail("source import failed");
        } finally {
            deleteQuietly(raw);
            if (safeStage) RootHelper.cleanupCameraStage(stagingPath);
        }
    }

    public Map<String,Object> importDocument(
            String kind, ParcelFileDescriptor descriptor) {
        File raw = null;
        File accepted = null;
        try {
            validateKind(kind);
            if (descriptor == null) throw new ValidationFailure("invalid document");
            synchronized (this) {
                ensureStateAvailable();
                raw = newPrivateFile("incoming-", ".tmp");
                accepted = "photo".equals(kind)
                        ? newPrivateFile("photo-", ".png")
                        : newPrivateFile("video-", ".bin");
                pendingImports.add(raw.getName());
                pendingImports.add(accepted.getName());
            }
            copyDocument(descriptor, raw, maxInputBytes(kind));
            if (raw.length() <= 0) throw new ValidationFailure("source is empty");
            ValidatedSource source = validateCandidate(kind, raw, accepted);
            synchronized (this) {
                ensureStateAvailable();
                State next = withSource(state, kind, source);
                Map<String,Object> result = commitMutation(next);
                if (!isRetainedSource(accepted)) deleteQuietly(accepted);
                return result;
            }
        } catch (ValidationFailure e) {
            deleteQuietly(accepted);
            synchronized (this) {
                return fail(e.safeMessage);
            }
        } catch (Throwable ignored) {
            deleteQuietly(accepted);
            synchronized (this) {
                return fail("document import failed");
            }
        } finally {
            closeQuietly(descriptor);
            synchronized (this) {
                deleteQuietly(raw);
                if (raw != null) pendingImports.remove(raw.getName());
                if (accepted != null) {
                    pendingImports.remove(accepted.getName());
                    if (!isRetainedSource(accepted)) deleteQuietly(accepted);
                }
            }
        }
    }

    /**
     * Returns a bounded UI-only rendering of an accepted app-private asset.
     * No source identifier or bytes are added to daemon status responses.
     */
    public synchronized Bitmap loadConfiguredThumbnail(
            String kind, int requestedWidth, int requestedHeight) {
        try {
            ensureStateAvailable();
            int maximumWidth = clampThumbnailDimension(requestedWidth);
            int maximumHeight = clampThumbnailDimension(requestedHeight);
            if ("photo".equals(kind) && state.photo != null) {
                File file = sourceFile(state.photo.fileName);
                verifyThumbnailSource(file, state.photo.size);
                return loadPhotoThumbnail(file, maximumWidth, maximumHeight);
            }
            if ("video".equals(kind) && state.video != null) {
                File file = sourceFile(state.video.fileName);
                verifyThumbnailSource(file, state.video.size);
                return loadVideoThumbnail(file, state.video, maximumWidth, maximumHeight);
            }
        } catch (Throwable ignored) {
            // A failed preview never changes or exposes the accepted camera state.
        }
        return null;
    }

    public synchronized Map<String,Object> setMode(String mode) {
        try {
            ensureStateAvailable();
            validateMode(mode);
            State next = new State(1, nextGeneration(), mode, false, state.photo, state.video);
            return commitMutation(next);
        } catch (ValidationFailure e) {
            return fail(e.safeMessage);
        } catch (Throwable ignored) {
            return fail("settings update failed");
        }
    }

    public synchronized Map<String,Object> clear(String kind) {
        try {
            if (!"photo".equals(kind) && !"video".equals(kind) && !"all".equals(kind)) {
                throw new ValidationFailure("invalid clear kind");
            }
            ensureStateAvailable();
            PhotoAsset photo = ("photo".equals(kind) || "all".equals(kind)) ? null : state.photo;
            VideoAsset video = ("video".equals(kind) || "all".equals(kind)) ? null : state.video;
            State next = new State(1, nextGeneration(), state.mode, false, photo, video);
            return commitMutation(next);
        } catch (ValidationFailure e) {
            return fail(e.safeMessage);
        } catch (Throwable ignored) {
            return fail("clear failed");
        }
    }

    public synchronized Map<String,Object> apply() {
        try {
            ensureStateAvailable();
            validateStateSources(state);
            if (!state.active) return commitMutation(state);
            publicationEpoch++;
            if (!reconcilePublication(state)) {
                publicationReady = false;
                throw new ValidationFailure("source activation failed");
            }
            publicationReady = true;
            lastError = "";
            return statusLocked(true);
        } catch (ValidationFailure e) {
            return fail(e.safeMessage);
        } catch (Throwable ignored) {
            return fail("apply failed");
        }
    }

    private Map<String,Object> commitMutation(State requested) {
        State previous = state;
        State active = new State(1, requested.generation, requested.mode, true,
                requested.photo, requested.video);
        try {
            publicationEpoch++;
            validateStateSources(active);
            try {
                commitState(active);
            } catch (Throwable commitFailure) {
                try {
                    commitState(previous);
                    state = previous;
                } catch (Throwable rollbackFailure) {
                    state = active;
                    stateAvailable = false;
                    publicationReady = false;
                    throw new ValidationFailure("state rollback failed");
                }
                throw new ValidationFailure("state commit failed");
            }

            boolean published;
            try {
                published = publish(active);
            } catch (Throwable ignored) {
                published = false;
            }
            if (!published) {
                try {
                    commitState(previous);
                } catch (Throwable rollbackFailure) {
                    state = active;
                    stateAvailable = false;
                    publicationReady = false;
                    throw new ValidationFailure("state rollback failed");
                }

                state = previous;
                stateAvailable = true;
                publicationReady = false;
                if (!restore(previous)) {
                    throw new ValidationFailure("state rollback failed");
                }
                publicationReady = true;
                RootHelper.cleanupCameraGeneration(active.generation);
                throw new ValidationFailure("source activation failed");
            }

            state = active;
            publicationReady = true;
            lastError = cleanupLocalFiles() ? "" : "orphan cleanup pending";
            if (previous.active && previous.generation != active.generation) {
                RootHelper.cleanupCameraGeneration(previous.generation);
            }
            return statusLocked(true);
        } catch (ValidationFailure e) {
            return fail(e.safeMessage);
        } catch (Throwable ignored) {
            return fail("source activation failed");
        }
    }

    private boolean publish(State value) throws ValidationFailure {
        return awaitPublication(() -> publishNow(value));
    }

    private boolean publishNow(State value) throws ValidationFailure {
        File photo = value.photo == null ? null : sourceFile(value.photo.fileName);
        File video = value.video == null ? null : sourceFile(value.video.fileName);
        return RootHelper.publishCameraGeneration(
                photo, video, value.generation, value.mode, Process.myUid());
    }

    private boolean restore(State previous) {
        try {
            return awaitPublication(() -> previous.active
                    ? publishNow(previous) : RootHelper.deactivateCameraPublication());
        } catch (Throwable ignored) {
            return false;
        }
    }

    private void reconcilePublicationLocked() {
        try {
            publicationReady = reconcilePublication(state);
            if (publicationReady) lastError = "";
            else lastError = "activation reconciliation pending";
        } catch (Throwable ignored) {
            publicationReady = false;
            lastError = "activation reconciliation pending";
        }
    }

    private boolean reconcilePublication(State value) throws ValidationFailure {
        return awaitPublication(() -> reconcilePublicationNow(value));
    }

    private boolean reconcilePublicationNow(State value) throws ValidationFailure {
        boolean activated = value.active
                ? publishNow(value) : RootHelper.deactivateCameraPublication();
        if (!activated) return false;
        return RootHelper.sweepCameraPublications(
                value.active ? value.generation : -1L,
                value.active && value.photo != null,
                value.active && value.video != null);
    }

    private boolean awaitPublication(Callable<Boolean> operation) throws ValidationFailure {
        try {
            return publicationExecutor.submit(operation).get();
        } catch (InterruptedException e) {
            Thread.currentThread().interrupt();
            throw new ValidationFailure("source activation failed");
        } catch (Throwable ignored) {
            throw new ValidationFailure("source activation failed");
        }
    }

    private void refreshReconciliationLocked() {
        if (reconciliationFuture == null || !reconciliationFuture.isDone()) return;
        PublicationResult result;
        try {
            result = reconciliationFuture.get();
        } catch (Throwable ignored) {
            result = null;
        }
        reconciliationFuture = null;
        if (result != null && result.epoch == publicationEpoch && result.state == state) {
            publicationReady = result.ready;
            lastError = result.ready ? "" : "activation reconciliation pending";
            reconciliationRetryAtMs = result.ready
                    ? 0L : SystemClock.elapsedRealtime() + RECONCILIATION_RETRY_DELAY_MS;
        } else {
            reconciliationRetryAtMs = 0L;
        }
    }

    private void scheduleReconciliationLocked() {
        if (!stateAvailable || publicationReady || reconciliationFuture != null
                || SystemClock.elapsedRealtime() < reconciliationRetryAtMs) {
            return;
        }
        final State expectedState = state;
        final long expectedEpoch = publicationEpoch;
        reconciliationFuture = publicationExecutor.submit(() -> {
            boolean ready;
            try {
                ready = reconcilePublicationNow(expectedState);
            } catch (Throwable ignored) {
                ready = false;
            }
            return new PublicationResult(expectedState, expectedEpoch, ready);
        });
    }

    private State withSource(State previous, String kind, ValidatedSource source)
            throws ValidationFailure {
        long generation = nextGeneration();
        if ("photo".equals(kind)) {
            return new State(1, generation, previous.mode, false,
                    source.photo, previous.video);
        }
        return new State(1, generation, previous.mode, false,
                previous.photo, source.video);
    }

    private long nextGeneration() throws ValidationFailure {
        if (state.generation == Long.MAX_VALUE) throw new ValidationFailure("generation exhausted");
        return state.generation + 1L;
    }

    private ValidatedSource validateCandidate(
            String kind, File raw, File accepted) throws ValidationFailure {
        long length = raw.length();
        validateDeclaredSize(kind, length);
        if ("photo".equals(kind)) return normalizePhoto(raw, accepted);
        VideoMetadata metadata = inspectVideo(raw);
        try {
            moveAtomic(raw, accepted);
            String digest = sha256(accepted);
            VideoAsset video = new VideoAsset(accepted.getName(), accepted.length(), digest,
                    metadata.width, metadata.height, metadata.durationMs,
                    metadata.rotation, metadata.codec);
            return ValidatedSource.video(accepted, video);
        } catch (ValidationFailure e) {
            deleteQuietly(accepted);
            throw e;
        } catch (Throwable ignored) {
            deleteQuietly(accepted);
            throw new ValidationFailure("video import failed");
        }
    }

    private ValidatedSource normalizePhoto(File raw, File output) throws ValidationFailure {
        Bitmap bitmap = null;
        FileOutputStream stream = null;
        try {
            bitmap = decodePhoto(raw);
            validateDimensions(bitmap.getWidth(), bitmap.getHeight(), "photo dimensions unsupported");
            stream = new FileOutputStream(output);
            Os.chmod(output.getAbsolutePath(), 0600);
            boolean compressed = bitmap.compress(Bitmap.CompressFormat.PNG, 100, stream);
            stream.flush();
            stream.getFD().sync();
            stream.close();
            stream = null;
            if (!compressed || output.length() <= 0 || output.length() > MAX_PHOTO_PNG_BYTES) {
                throw new ValidationFailure("normalized photo too large");
            }
            syncDirectory(directory);
            PhotoAsset photo = new PhotoAsset(output.getName(), output.length(), sha256(output),
                    bitmap.getWidth(), bitmap.getHeight());
            return ValidatedSource.photo(output, photo);
        } catch (ValidationFailure e) {
            deleteQuietly(output);
            throw e;
        } catch (Throwable ignored) {
            deleteQuietly(output);
            throw new ValidationFailure("photo decode failed");
        } finally {
            if (stream != null) {
                try { stream.close(); } catch (Throwable ignored) { }
            }
            if (bitmap != null) bitmap.recycle();
        }
    }

    private Bitmap decodePhoto(File file) throws ValidationFailure {
        try {
            ImageDecoder.Source source = ImageDecoder.createSource(file);
            Bitmap bitmap = ImageDecoder.decodeBitmap(source, (decoder, info, ignored) -> {
                String mime = info.getMimeType();
                if (!"image/jpeg".equals(mime) && !"image/png".equals(mime)) {
                    throw new UnsupportedPhotoFormat();
                }
                int width = info.getSize().getWidth();
                int height = info.getSize().getHeight();
                if (!dimensionsAllowed(width, height)) throw new DecodeGuard();
                decoder.setAllocator(ImageDecoder.ALLOCATOR_SOFTWARE);
                decoder.setMemorySizePolicy(ImageDecoder.MEMORY_POLICY_LOW_RAM);
            });
            if (bitmap == null || !dimensionsAllowed(bitmap.getWidth(), bitmap.getHeight())) {
                if (bitmap != null) bitmap.recycle();
                throw new ValidationFailure("photo dimensions unsupported");
            }
            return bitmap;
        } catch (UnsupportedPhotoFormat ignored) {
            throw new ValidationFailure("photo format unsupported");
        } catch (DecodeGuard ignored) {
            throw new ValidationFailure("photo dimensions unsupported");
        } catch (ValidationFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new ValidationFailure("photo decode failed");
        }
    }

    private VideoMetadata inspectVideo(File file) throws ValidationFailure {
        MediaExtractor extractor = new MediaExtractor();
        MediaCodec codec = null;
        ImageReader reader = null;
        boolean codecStarted = false;
        try {
            extractor.setDataSource(file.getAbsolutePath());
            int track = -1;
            MediaFormat format = null;
            String mime = null;
            for (int i = 0; i < extractor.getTrackCount(); i++) {
                MediaFormat candidate = extractor.getTrackFormat(i);
                String candidateMime = candidate.getString(MediaFormat.KEY_MIME);
                if (candidateMime != null && candidateMime.startsWith("video/")) {
                    track = i;
                    format = candidate;
                    mime = candidateMime;
                    break;
                }
            }
            if (track < 0 || format == null || !isSupportedVideoCodec(mime)) {
                throw new ValidationFailure("video track unsupported");
            }
            int width = requireFormatInt(format, MediaFormat.KEY_WIDTH);
            int height = requireFormatInt(format, MediaFormat.KEY_HEIGHT);
            validateDimensions(width, height, "video dimensions unsupported");
            long durationUs = requireFormatLong(format, MediaFormat.KEY_DURATION);
            if (durationUs <= 0 || durationUs > MAX_VIDEO_DURATION_US) {
                throw new ValidationFailure("video duration unsupported");
            }
            int rotation = format.containsKey(MediaFormat.KEY_ROTATION)
                    ? requireFormatInt(format, MediaFormat.KEY_ROTATION) : 0;
            rotation = ((rotation % 360) + 360) % 360;
            if (rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270) {
                throw new ValidationFailure("video rotation unsupported");
            }
            validateVideoColorMetadata(format);

            extractor.selectTrack(track);
            reader = ImageReader.newInstance(width, height, ImageFormat.YUV_420_888, 2);
            codec = MediaCodec.createDecoderByType(mime);
            codec.configure(format, reader.getSurface(), null, 0);
            codec.start();
            codecStarted = true;
            boolean inputDone = false;
            boolean frameDecoded = false;
            long deadline = SystemClock.elapsedRealtime() + VIDEO_DECODE_TIMEOUT_MS;
            MediaCodec.BufferInfo info = new MediaCodec.BufferInfo();
            while (!frameDecoded && SystemClock.elapsedRealtime() < deadline) {
                if (!inputDone) {
                    int inputIndex = codec.dequeueInputBuffer(10000);
                    if (inputIndex >= 0) {
                        ByteBuffer input = codec.getInputBuffer(inputIndex);
                        if (input == null) throw new ValidationFailure("video frame decode failed");
                        input.clear();
                        int sampleSize = extractor.readSampleData(input, 0);
                        if (sampleSize < 0) {
                            codec.queueInputBuffer(inputIndex, 0, 0, 0,
                                    MediaCodec.BUFFER_FLAG_END_OF_STREAM);
                            inputDone = true;
                        } else {
                            codec.queueInputBuffer(inputIndex, 0, sampleSize,
                                    Math.max(0L, extractor.getSampleTime()), 0);
                            extractor.advance();
                        }
                    }
                }
                int outputIndex = codec.dequeueOutputBuffer(info, 10000);
                if (outputIndex >= 0) {
                    boolean render = (info.flags & MediaCodec.BUFFER_FLAG_CODEC_CONFIG) == 0;
                    codec.releaseOutputBuffer(outputIndex, render);
                    if (render) {
                        long imageDeadline = Math.min(
                                deadline, SystemClock.elapsedRealtime() + 1000L);
                        Image image = null;
                        while (image == null && SystemClock.elapsedRealtime() < imageDeadline) {
                            image = reader.acquireLatestImage();
                            if (image == null) SystemClock.sleep(2L);
                        }
                        if (image != null) {
                            try {
                                Image.Plane[] planes = image.getPlanes();
                                boolean hasBytes = false;
                                if (planes != null) {
                                    for (Image.Plane plane : planes) {
                                        ByteBuffer buffer = plane == null ? null : plane.getBuffer();
                                        if (buffer != null && buffer.remaining() > 0) {
                                            hasBytes = true;
                                            break;
                                        }
                                    }
                                }
                                frameDecoded = image.getWidth() == width
                                        && image.getHeight() == height
                                        && planes != null && planes.length > 0 && hasBytes;
                            } finally {
                                image.close();
                            }
                        }
                    }
                    if ((info.flags & MediaCodec.BUFFER_FLAG_END_OF_STREAM) != 0
                            && !frameDecoded) {
                        break;
                    }
                }
            }
            if (!frameDecoded) throw new ValidationFailure("video frame decode failed");
            long durationMs = Math.max(1L, (durationUs + 999L) / 1000L);
            return new VideoMetadata(width, height, durationMs, rotation, mime);
        } catch (ValidationFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new ValidationFailure("video decode failed");
        } finally {
            if (codec != null) {
                if (codecStarted) {
                    try { codec.stop(); } catch (Throwable ignored) { }
                }
                try { codec.release(); } catch (Throwable ignored) { }
            }
            if (reader != null) {
                try { reader.close(); } catch (Throwable ignored) { }
            }
            try { extractor.release(); } catch (Throwable ignored) { }
        }
    }

    private void validatePersistedStateSources(State value) throws Exception {
        if (value.photo != null) {
            verifyPersistedPrivateFile(
                    sourceFile(value.photo.fileName), value.photo.size, value.photo.sha256);
        }
        if (value.video != null) {
            verifyPersistedPrivateFile(
                    sourceFile(value.video.fileName), value.video.size, value.video.sha256);
        }
    }

    private void verifyPersistedPrivateFile(File file, long size, String digest)
            throws Exception {
        if (!Files.exists(file.toPath(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(file.toPath())
                || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)
                || !directory.getCanonicalFile().equals(file.getCanonicalFile().getParentFile())) {
            throw new InvalidPersistedState();
        }
        android.system.StructStat sourceStat = Os.lstat(file.getAbsolutePath());
        if (sourceStat.st_uid != Process.myUid() || sourceStat.st_size != size
                || !constantTimeEquals(sha256Checked(file), digest)) {
            throw new InvalidPersistedState();
        }
    }

    private void validateStateSources(State value) throws ValidationFailure {
        if (value.photo != null) {
            File photoFile = sourceFile(value.photo.fileName);
            verifyPrivateFile(photoFile, value.photo.size, value.photo.sha256);
            Bitmap bitmap = decodePhoto(photoFile);
            try {
                if (bitmap.getWidth() != value.photo.width || bitmap.getHeight() != value.photo.height) {
                    throw new ValidationFailure("photo metadata mismatch");
                }
            } finally {
                bitmap.recycle();
            }
        }
        if (value.video != null) {
            File videoFile = sourceFile(value.video.fileName);
            verifyPrivateFile(videoFile, value.video.size, value.video.sha256);
            VideoMetadata actual = inspectVideo(videoFile);
            if (actual.width != value.video.width || actual.height != value.video.height
                    || actual.durationMs != value.video.durationMs
                    || actual.rotation != value.video.rotation
                    || !actual.codec.equals(value.video.codec)) {
                throw new ValidationFailure("video metadata mismatch");
            }
        }
    }

    private void verifyPrivateFile(File file, long size, String digest) throws ValidationFailure {
        try {
            File canonicalDirectory = directory.getCanonicalFile();
            File canonicalFile = file.getCanonicalFile();
            boolean parentMatches = canonicalDirectory.equals(canonicalFile.getParentFile());
            boolean symbolicLink = Files.isSymbolicLink(file.toPath());
            boolean regularFile = Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS);
            boolean ownerMatches = Os.lstat(file.getAbsolutePath()).st_uid == Process.myUid();
            boolean sizeMatches = file.length() == size;
            boolean digestMatches = constantTimeEquals(sha256(file), digest);
            if (!parentMatches || symbolicLink || !regularFile
                    || !ownerMatches || !sizeMatches || !digestMatches) {
                android.util.Log.e("CameraMediaManager",
                        "private source rejected:"
                                + " parent=" + parentMatches
                                + " symlink=" + symbolicLink
                                + " regular=" + regularFile
                                + " owner=" + ownerMatches
                                + " size=" + sizeMatches
                                + " digest=" + digestMatches);
                throw new ValidationFailure("accepted source unavailable");
            }
        } catch (ValidationFailure e) {
            throw e;
        } catch (Throwable ignored) {
            android.util.Log.e("CameraMediaManager",
                    "private source validation failed: " + ignored.getClass().getSimpleName());
            throw new ValidationFailure("accepted source unavailable");
        }
    }

    private void copyDocument(
            ParcelFileDescriptor descriptor, File destination, long maximum)
            throws ValidationFailure {
        DocumentCopyTask task = new DocumentCopyTask(descriptor, destination, maximum);
        Future<Void> future = documentCopyExecutor.submit(task);
        try {
            future.get(DOCUMENT_COPY_TIMEOUT_MS, TimeUnit.MILLISECONDS);
        } catch (TimeoutException e) {
            task.cancel();
            future.cancel(true);
            deleteQuietly(destination);
            throw new ValidationFailure("document unavailable");
        } catch (InterruptedException e) {
            task.cancel();
            future.cancel(true);
            Thread.currentThread().interrupt();
            throw new ValidationFailure("document unavailable");
        } catch (ExecutionException e) {
            Throwable cause = e.getCause();
            if (cause instanceof ValidationFailure) {
                throw (ValidationFailure) cause;
            }
            throw new ValidationFailure("document unavailable");
        }
    }

    private State loadState() throws Exception {
        if (!stateFile.exists()) return State.empty();
        if (!Files.isRegularFile(stateFile.toPath(), LinkOption.NOFOLLOW_LINKS)
                || Files.isSymbolicLink(stateFile.toPath()) || stateFile.length() > 65536L
                || Os.lstat(stateFile.getAbsolutePath()).st_uid != Process.myUid()) {
            throw new InvalidPersistedState();
        }
        byte[] bytes = Files.readAllBytes(stateFile.toPath());
        try {
            JSONObject object = new JSONObject(new String(bytes, "UTF-8"));
            requireKeys(object, "version", "generation", "mode", "active", "photo", "video");
            if (object.getInt("version") != 1) throw new InvalidPersistedState();
            long generation = object.getLong("generation");
            if (generation < 0) throw new InvalidPersistedState();
            String mode = object.getString("mode");
            validateMode(mode);
            boolean active = object.getBoolean("active");
            PhotoAsset photo = object.isNull("photo")
                    ? null : PhotoAsset.fromJson(object.getJSONObject("photo"));
            VideoAsset video = object.isNull("video")
                    ? null : VideoAsset.fromJson(object.getJSONObject("video"));
            return new State(1, generation, mode, active, photo, video);
        } catch (InvalidPersistedState e) {
            throw e;
        } catch (Exception invalidState) {
            throw new InvalidPersistedState();
        }
    }

    private File prepareState(State value) throws Exception {
        JSONObject object = new JSONObject();
        object.put("version", 1);
        object.put("generation", value.generation);
        object.put("mode", value.mode);
        object.put("active", value.active);
        object.put("photo", value.photo == null ? JSONObject.NULL : value.photo.toJson());
        object.put("video", value.video == null ? JSONObject.NULL : value.video.toJson());
        byte[] bytes = object.toString().getBytes("UTF-8");
        File prepared = new File(directory, ".state-" + randomId() + ".tmp");
        FileOutputStream output = null;
        try {
            output = new FileOutputStream(prepared);
            Os.chmod(prepared.getAbsolutePath(), 0600);
            output.write(bytes);
            output.flush();
            output.getFD().sync();
            return prepared;
        } catch (Exception failure) {
            deleteQuietly(prepared);
            throw failure;
        } catch (Error failure) {
            deleteQuietly(prepared);
            throw failure;
        } finally {
            if (output != null) {
                try { output.close(); } catch (Throwable ignored) { }
            }
        }
    }

    private void commitPrepared(File prepared) throws Exception {
        try {
            Files.move(prepared.toPath(), stateFile.toPath(),
                    StandardCopyOption.ATOMIC_MOVE, StandardCopyOption.REPLACE_EXISTING);
            syncDirectory(directory);
        } catch (AtomicMoveNotSupportedException e) {
            throw new ValidationFailure("state commit failed");
        }
    }

    private void commitState(State value) throws Exception {
        File prepared = prepareState(value);
        try {
            commitPrepared(prepared);
        } finally {
            deleteQuietly(prepared);
        }
    }

    private boolean cleanupLocalFiles() {
        boolean changed = false;
        try {
            Set<String> retained = new HashSet<>();
            retained.add(STATE_NAME);
            retained.addAll(pendingImports);
            if (state.photo != null) retained.add(state.photo.fileName);
            if (state.video != null) retained.add(state.video.fileName);
            File[] files = directory.listFiles();
            if (files == null) return false;
            for (File file : files) {
                if (!retained.contains(file.getName()) && file.isFile()
                        && (file.getName().startsWith("incoming-")
                        || file.getName().startsWith("photo-")
                        || file.getName().startsWith("video-")
                        || file.getName().startsWith(".state-"))) {
                    if (!file.delete() && file.exists()) return false;
                    changed = true;
                }
            }
            if (changed) syncDirectory(directory);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private Map<String,Object> statusLocked(boolean ok) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("ok", ok);
        result.put("mode", state.mode);
        result.put("generation", state.generation);
        result.put("active", state.active && publicationReady);
        result.put("photoConfigured", state.photo != null);
        result.put("photoWidth", state.photo == null ? 0 : state.photo.width);
        result.put("photoHeight", state.photo == null ? 0 : state.photo.height);
        result.put("videoConfigured", state.video != null);
        result.put("videoWidth", state.video == null ? 0 : state.video.width);
        result.put("videoHeight", state.video == null ? 0 : state.video.height);
        result.put("videoDurationMs", state.video == null ? 0L : state.video.durationMs);
        result.put("videoCodec", state.video == null ? "" : state.video.codec);
        result.put("videoRotation", state.video == null ? 0 : state.video.rotation);
        result.put("lastError", lastError);
        if (!ok) result.put("error", lastError);
        return result;
    }

    private Map<String,Object> fail(String safeMessage) {
        lastError = safeMessage == null || safeMessage.length() > 80
                ? "camera operation failed" : safeMessage;
        return statusLocked(false);
    }

    private static Map<String,Object> minimalFailure(String safeMessage) {
        Map<String,Object> result = new LinkedHashMap<>();
        result.put("ok", false);
        result.put("mode", DEFAULT_MODE);
        result.put("generation", 0L);
        result.put("active", false);

        result.put("photoConfigured", false);

        result.put("photoWidth", 0);
        result.put("photoHeight", 0);
        result.put("videoConfigured", false);
        result.put("videoWidth", 0);
        result.put("videoHeight", 0);
        result.put("videoDurationMs", 0L);
        result.put("videoCodec", "");
        result.put("videoRotation", 0);
        result.put("lastError", safeMessage);
        result.put("error", safeMessage);
        return result;
    }
    static Map<String,Object> notReadyStatus() {
        return minimalFailure("camera service not ready");
    }

    private boolean isRetainedSource(File file) {
        if (file == null) return false;
        String name = file.getName();
        return (state.photo != null && name.equals(state.photo.fileName))
                || (state.video != null && name.equals(state.video.fileName));
    }


    private File sourceFile(String name) throws ValidationFailure {
        if (name == null || !name.matches("(?:photo-[0-9a-f]{32}\\.png|video-[0-9a-f]{32}\\.bin)")) {
            throw new ValidationFailure("state unavailable");
        }
        File file = new File(directory, name);
        try {
            if (!directory.getCanonicalFile().equals(file.getCanonicalFile().getParentFile())) {
                throw new ValidationFailure("state unavailable");
            }
        } catch (ValidationFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new ValidationFailure("state unavailable");
        }
        return file;
    }

    private File newPrivateFile(String prefix, String suffix) throws ValidationFailure {
        File file = new File(directory, prefix + randomId() + suffix);
        try {
            if (file.exists() || !directory.getCanonicalFile().equals(file.getCanonicalFile().getParentFile())) {
                throw new ValidationFailure("private storage unavailable");
            }
            return file;
        } catch (ValidationFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new ValidationFailure("private storage unavailable");
        }
    }

    private static String randomId() {
        return UUID.randomUUID().toString().replace("-", "").toLowerCase(Locale.ROOT);
    }

    private void moveAtomic(File source, File destination) throws ValidationFailure {
        try {
            Files.move(source.toPath(), destination.toPath(), StandardCopyOption.ATOMIC_MOVE);
            syncDirectory(directory);
        } catch (Throwable ignored) {
            throw new ValidationFailure("private storage unavailable");
        }
    }

    private static String sha256(File file) throws ValidationFailure {
        try {
            return sha256Checked(file);
        } catch (Throwable ignored) {
            throw new ValidationFailure("source verification failed");
        }
    }

    private static String sha256Checked(File file) throws Exception {
        MessageDigest digest = MessageDigest.getInstance("SHA-256");
        FileInputStream input = new FileInputStream(file);
        try {
            byte[] buffer = new byte[128 * 1024];
            int count;
            while ((count = input.read(buffer)) >= 0) {
                if (count > 0) digest.update(buffer, 0, count);
            }
        } finally {
            input.close();
        }
        byte[] value = digest.digest();
        char[] hex = new char[value.length * 2];
        final char[] alphabet = "0123456789abcdef".toCharArray();
        for (int i = 0; i < value.length; i++) {
            int b = value[i] & 0xff;
            hex[i * 2] = alphabet[b >>> 4];
            hex[i * 2 + 1] = alphabet[b & 15];
        }
        return new String(hex);
    }
    private void ensureStateAvailable() throws ValidationFailure {
        if (!stateAvailable) throw new ValidationFailure("state unavailable");
        if (!publicationReady) {
            reconcilePublicationLocked();
            if (!publicationReady) throw new ValidationFailure("activation unavailable");
        }
    }

    private void verifyThumbnailSource(File file, long size) throws Exception {
        if (!directory.getCanonicalFile().equals(file.getCanonicalFile().getParentFile())
                || Files.isSymbolicLink(file.toPath())
                || !Files.isRegularFile(file.toPath(), LinkOption.NOFOLLOW_LINKS)
                || Os.lstat(file.getAbsolutePath()).st_uid != Process.myUid()
                || file.length() != size) {
            throw new ValidationFailure("preview unavailable");
        }
    }

    private Bitmap loadPhotoThumbnail(File file, int maximumWidth, int maximumHeight)
            throws Exception {
        BitmapFactory.Options bounds = new BitmapFactory.Options();
        bounds.inJustDecodeBounds = true;
        BitmapFactory.decodeFile(file.getAbsolutePath(), bounds);
        if (!dimensionsAllowed(bounds.outWidth, bounds.outHeight)) {
            throw new ValidationFailure("preview unavailable");
        }
        int[] target = boundedSize(
                bounds.outWidth, bounds.outHeight, maximumWidth, maximumHeight);
        int sample = 1;
        while (bounds.outWidth / (sample * 2) >= target[0]
                && bounds.outHeight / (sample * 2) >= target[1]) {
            sample *= 2;
        }
        BitmapFactory.Options options = new BitmapFactory.Options();
        options.inSampleSize = sample;
        options.inPreferredConfig = Bitmap.Config.ARGB_8888;
        Bitmap decoded = BitmapFactory.decodeFile(file.getAbsolutePath(), options);
        if (decoded == null) throw new ValidationFailure("preview unavailable");
        return scaleOwnedBitmap(decoded, target[0], target[1]);
    }

    private Bitmap loadVideoThumbnail(
            File file, VideoAsset asset, int maximumWidth, int maximumHeight)
            throws Exception {
        int displayWidth = (asset.rotation == 90 || asset.rotation == 270)
                ? asset.height : asset.width;
        int displayHeight = (asset.rotation == 90 || asset.rotation == 270)
                ? asset.width : asset.height;
        int[] target = boundedSize(
                displayWidth, displayHeight, maximumWidth, maximumHeight);
        MediaMetadataRetriever retriever = new MediaMetadataRetriever();
        FileInputStream input = new FileInputStream(file);
        try {
            retriever.setDataSource(input.getFD());
            Bitmap frame = retriever.getScaledFrameAtTime(
                    0L, MediaMetadataRetriever.OPTION_CLOSEST, target[0], target[1]);
            if (frame == null) throw new ValidationFailure("preview unavailable");
            int[] actualTarget = boundedSize(
                    frame.getWidth(), frame.getHeight(), maximumWidth, maximumHeight);
            return scaleOwnedBitmap(frame, actualTarget[0], actualTarget[1]);
        } finally {
            closeQuietly(input);
            try { retriever.release(); } catch (Throwable ignored) { }
        }
    }

    private static Bitmap scaleOwnedBitmap(Bitmap source, int width, int height) {
        if (source.getWidth() == width && source.getHeight() == height) return source;
        Bitmap scaled = Bitmap.createScaledBitmap(source, width, height, true);
        source.recycle();
        return scaled;
    }

    private static int[] boundedSize(
            int width, int height, int maximumWidth, int maximumHeight)
            throws ValidationFailure {
        if (width <= 0 || height <= 0) throw new ValidationFailure("preview unavailable");
        double scale = Math.min(
                1.0d, Math.min((double) maximumWidth / width, (double) maximumHeight / height));
        return new int[] {
                Math.max(1, (int) Math.round(width * scale)),
                Math.max(1, (int) Math.round(height * scale))
        };
    }

    private static int clampThumbnailDimension(int requested) {
        return Math.max(32, Math.min(512, requested));
    }

    private static void syncDirectory(File value) throws Exception {
        if (value == null) throw new ValidationFailure("storage sync failed");
        FileDescriptor descriptor = Os.open(value.getAbsolutePath(), OsConstants.O_RDONLY, 0);
        try {
            Os.fsync(descriptor);
        } finally {
            Os.close(descriptor);
        }
    }

    private static void closeQuietly(java.io.Closeable value) {
        if (value != null) {
            try { value.close(); } catch (Throwable ignored) { }
        }
    }


    private static boolean constantTimeEquals(String left, String right) {
        if (left == null || right == null) return false;
        return MessageDigest.isEqual(left.getBytes(), right.getBytes());
    }

    private static boolean isStagePath(String path) {
        return path != null && path.matches("/data/local/tmp/\\.camera-upload-[0-9a-f]{32}");
    }

    private static void validateKind(String kind) throws ValidationFailure {
        if (!"photo".equals(kind) && !"video".equals(kind)) {
            throw new ValidationFailure("invalid source kind");
        }
    }

    private static void validateMode(String mode) throws ValidationFailure {
        if (!"naturalized".equals(mode) && !"faithful".equals(mode)) {
            throw new ValidationFailure("invalid camera mode");
        }
    }

    private static long maxInputBytes(String kind) {
        return "photo".equals(kind) ? MAX_PHOTO_INPUT_BYTES : MAX_VIDEO_BYTES;
    }

    private static void validateDeclaredSize(String kind, long size) throws ValidationFailure {
        if (size <= 0 || size > maxInputBytes(kind)) {
            throw new ValidationFailure("source size out of range");
        }
    }

    private static boolean dimensionsAllowed(int width, int height) {
        return width > 0 && height > 0 && width <= MAX_DIMENSION && height <= MAX_DIMENSION
                && (long) width * (long) height <= MAX_PIXELS;
    }

    private static void validateDimensions(int width, int height, String error)
            throws ValidationFailure {
        if (!dimensionsAllowed(width, height)) throw new ValidationFailure(error);
    }

    private static boolean isSupportedVideoCodec(String codec) {
        return "video/avc".equals(codec) || "video/hevc".equals(codec);
    }

    private static void validateVideoColorMetadata(MediaFormat format)
            throws ValidationFailure {
        try {
            if (format.containsKey(MediaFormat.KEY_COLOR_STANDARD)) {
                int standard = format.getInteger(MediaFormat.KEY_COLOR_STANDARD);
                if (standard != COLOR_METADATA_UNSPECIFIED
                        && standard != MediaFormat.COLOR_STANDARD_BT601_NTSC
                        && standard != MediaFormat.COLOR_STANDARD_BT601_PAL
                        && standard != MediaFormat.COLOR_STANDARD_BT709) {
                    throw new ValidationFailure("video color metadata unsupported");
                }
            }
            if (format.containsKey(MediaFormat.KEY_COLOR_RANGE)) {
                int range = format.getInteger(MediaFormat.KEY_COLOR_RANGE);
                if (range != COLOR_METADATA_UNSPECIFIED
                        && range != MediaFormat.COLOR_RANGE_LIMITED
                        && range != MediaFormat.COLOR_RANGE_FULL) {
                    throw new ValidationFailure("video color metadata unsupported");
                }
            }
            if (format.containsKey(MediaFormat.KEY_COLOR_TRANSFER)) {
                int transfer = format.getInteger(MediaFormat.KEY_COLOR_TRANSFER);
                if (transfer != COLOR_METADATA_UNSPECIFIED
                        && transfer != MediaFormat.COLOR_TRANSFER_SDR_VIDEO
                        && transfer != COLOR_TRANSFER_SRGB) {
                    throw new ValidationFailure("video color metadata unsupported");
                }
            }
        } catch (ValidationFailure e) {
            throw e;
        } catch (Throwable ignored) {
            throw new ValidationFailure("video color metadata unsupported");
        }
    }

    private static int requireFormatInt(MediaFormat format, String key) throws ValidationFailure {
        try {
            return format.getInteger(key);
        } catch (Throwable ignored) {
            throw new ValidationFailure("video metadata unavailable");
        }
    }

    private static long requireFormatLong(MediaFormat format, String key) throws ValidationFailure {
        try {
            return format.getLong(key);
        } catch (Throwable ignored) {
            try {
                return format.getInteger(key);
            } catch (Throwable ignoredAgain) {
                throw new ValidationFailure("video metadata unavailable");
            }
        }
    }

    private static void requireKeys(JSONObject object, String... expected) throws Exception {
        Set<String> allowed = new HashSet<>(Arrays.asList(expected));
        if (object.length() != allowed.size()) throw new ValidationFailure("state unavailable");
        Iterator<String> keys = object.keys();
        while (keys.hasNext()) {
            if (!allowed.contains(keys.next())) throw new ValidationFailure("state unavailable");
        }
    }

    private static void deleteQuietly(File file) {
        if (file == null) return;
        try {
            if (file.isFile() && !Files.isSymbolicLink(file.toPath())) file.delete();
        } catch (Throwable ignored) { }
    }

    private static final class DocumentCopyTask implements Callable<Void> {
        private final Object lock = new Object();
        private final ParcelFileDescriptor descriptor;
        private final File destination;
        private final long maximum;
        private volatile boolean canceled;
        private InputStream input;
        private FileOutputStream output;

        DocumentCopyTask(ParcelFileDescriptor descriptor, File destination, long maximum) {
            this.descriptor = descriptor;
            this.destination = destination;
            this.maximum = maximum;
        }

        @Override
        public Void call() throws ValidationFailure {
            try {
                synchronized (lock) {
                    if (canceled) throw new ValidationFailure("document unavailable");
                    input = new ParcelFileDescriptor.AutoCloseInputStream(descriptor);
                    output = new FileOutputStream(destination);
                    Os.chmod(destination.getAbsolutePath(), 0600);
                }
                byte[] buffer = new byte[128 * 1024];
                long total = 0L;
                while (true) {
                    if (canceled || Thread.currentThread().isInterrupted()) {
                        throw new ValidationFailure("document unavailable");
                    }
                    int count = input.read(buffer);
                    if (count < 0) break;
                    if (count == 0) continue;
                    total += count;
                    if (total > maximum) throw new ValidationFailure("source too large");
                    output.write(buffer, 0, count);
                }
                if (canceled) throw new ValidationFailure("document unavailable");
                output.flush();
                output.getFD().sync();
                return null;
            } catch (ValidationFailure e) {
                deleteQuietly(destination);
                throw e;
            } catch (Throwable ignored) {
                deleteQuietly(destination);
                throw new ValidationFailure("document unavailable");
            } finally {
                closeQuietly(input);
                closeQuietly(output);
                closeQuietly(descriptor);
            }
        }

        void cancel() {
            synchronized (lock) {
                canceled = true;
                closeQuietly(input);
                closeQuietly(output);
                closeQuietly(descriptor);
            }
            deleteQuietly(destination);
        }
    }

    private static final class State {
        final int version;
        final long generation;
        final String mode;
        final boolean active;
        final PhotoAsset photo;
        final VideoAsset video;

        State(int version, long generation, String mode, boolean active,
                PhotoAsset photo, VideoAsset video) {
            this.version = version;
            this.generation = generation;
            this.mode = mode;
            this.active = active;
            this.photo = photo;
            this.video = video;
        }

        static State empty() {
            return new State(1, 0L, DEFAULT_MODE, false, null, null);
        }
    }

    private static final class PhotoAsset {
        final String fileName;
        final long size;
        final String sha256;
        final int width;
        final int height;

        PhotoAsset(String fileName, long size, String sha256, int width, int height) {
            this.fileName = fileName;
            this.size = size;
            this.sha256 = sha256;
            this.width = width;
            this.height = height;
        }

        JSONObject toJson() throws Exception {
            JSONObject object = new JSONObject();
            object.put("file", fileName);
            object.put("size", size);
            object.put("sha256", sha256);
            object.put("width", width);
            object.put("height", height);
            return object;
        }

        static PhotoAsset fromJson(JSONObject object) throws Exception {
            requireKeys(object, "file", "size", "sha256", "width", "height");
            String file = object.getString("file");
            long size = object.getLong("size");
            String digest = object.getString("sha256");
            int width = object.getInt("width");
            int height = object.getInt("height");
            if (!file.matches("photo-[0-9a-f]{32}\\.png") || size <= 0
                    || size > MAX_PHOTO_PNG_BYTES || !digest.matches("[0-9a-f]{64}")
                    || !dimensionsAllowed(width, height)) {
                throw new ValidationFailure("state unavailable");
            }
            return new PhotoAsset(file, size, digest, width, height);
        }
    }

    private static final class VideoAsset {
        final String fileName;
        final long size;
        final String sha256;
        final int width;
        final int height;
        final long durationMs;
        final int rotation;
        final String codec;

        VideoAsset(String fileName, long size, String sha256, int width, int height,
                long durationMs, int rotation, String codec) {
            this.fileName = fileName;
            this.size = size;
            this.sha256 = sha256;
            this.width = width;
            this.height = height;
            this.durationMs = durationMs;
            this.rotation = rotation;
            this.codec = codec;
        }

        JSONObject toJson() throws Exception {
            JSONObject object = new JSONObject();
            object.put("file", fileName);
            object.put("size", size);
            object.put("sha256", sha256);
            object.put("width", width);
            object.put("height", height);
            object.put("durationMs", durationMs);
            object.put("rotation", rotation);
            object.put("codec", codec);
            return object;
        }

        static VideoAsset fromJson(JSONObject object) throws Exception {
            requireKeys(object, "file", "size", "sha256", "width", "height",
                    "durationMs", "rotation", "codec");
            String file = object.getString("file");
            long size = object.getLong("size");
            String digest = object.getString("sha256");
            int width = object.getInt("width");
            int height = object.getInt("height");
            long durationMs = object.getLong("durationMs");
            int rotation = object.getInt("rotation");
            String codec = object.getString("codec");
            if (!file.matches("video-[0-9a-f]{32}\\.bin") || size <= 0 || size > MAX_VIDEO_BYTES
                    || !digest.matches("[0-9a-f]{64}") || !dimensionsAllowed(width, height)
                    || durationMs <= 0 || durationMs > MAX_VIDEO_DURATION_US / 1000L
                    || (rotation != 0 && rotation != 90 && rotation != 180 && rotation != 270)
                    || !isSupportedVideoCodec(codec)) {
                throw new ValidationFailure("state unavailable");
            }
            return new VideoAsset(file, size, digest, width, height, durationMs, rotation, codec);
        }
    }

    private static final class ValidatedSource {
        final File file;
        final PhotoAsset photo;
        final VideoAsset video;

        private ValidatedSource(File file, PhotoAsset photo, VideoAsset video) {
            this.file = file;
            this.photo = photo;
            this.video = video;
        }

        static ValidatedSource photo(File file, PhotoAsset photo) {
            return new ValidatedSource(file, photo, null);
        }

        static ValidatedSource video(File file, VideoAsset video) {
            return new ValidatedSource(file, null, video);
        }
    }

    private static final class VideoMetadata {
        final int width;
        final int height;
        final long durationMs;
        final int rotation;
        final String codec;

        VideoMetadata(int width, int height, long durationMs, int rotation, String codec) {
            this.width = width;
            this.height = height;
            this.durationMs = durationMs;
            this.rotation = rotation;
            this.codec = codec;
        }
    }

    private static final class PublicationResult {
        final State state;
        final long epoch;
        final boolean ready;

        PublicationResult(State state, long epoch, boolean ready) {
            this.state = state;
            this.epoch = epoch;
            this.ready = ready;
        }
    }

    private static final class InvalidPersistedState extends Exception {
        InvalidPersistedState() {
            super("state unavailable");
        }
    }

    private static final class ValidationFailure extends Exception {
        final String safeMessage;

        ValidationFailure(String safeMessage) {
            super(safeMessage);
            this.safeMessage = safeMessage;
        }
    }

    private static final class UnsupportedPhotoFormat extends RuntimeException { }

    private static final class DecodeGuard extends RuntimeException { }
}
