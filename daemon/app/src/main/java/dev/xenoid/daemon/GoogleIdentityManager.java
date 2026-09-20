package dev.xenoid.daemon;

import android.content.ComponentName;
import android.content.Context;
import android.content.Intent;
import android.content.ServiceConnection;
import android.database.Cursor;
import android.net.Uri;
import android.os.IBinder;
import android.os.Parcel;
import android.os.RemoteException;

import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Keeps microG's app-facing GAID live and publishes the journaled GSF ID.
 *
 * <p>Durability model for the pinned microG build: MemoryAdvertisingIdConfiguration
 * holds the GAID only in memory (a fresh random UUID minted by its constructor),
 * and its binder surface exposes read/reset/global-limit operations only — there is
 * no exact-ID setter, so an exact GAID can never be reapplied after the GMS process
 * dies.  The truthful guarantee is therefore nonzero self-heal: whenever the
 * offline-seeded marker exists, every construction/rebind/status clears the global
 * ad-tracking limit and requires a nonzero, well-formed GAID before reporting
 * success; a recreated GMS process simply mints a fresh random GAID, which is an
 * acceptable new observation.  The reported advertisingIdSha256 is always an
 * observation of the live service, never a replayed stored value.  The GSF Android
 * ID stays the exact, fixed target seeded into gservices.db and the protected
 * /data/local/tmp/xenoid-profile/gsf_android_id marker, and status fails closed if
 * the provider value diverges from that marker.
 *
 * <p>All operations are serialized on opLock end to end: the offline seed rewrites
 * microG state under force-stop, so no concurrent status may bind or read during
 * that window, and concurrent activates cannot share the fixed staging names.
 * Binder state is generation-guarded per connection: callbacks from a superseded
 * connection can never clear the live binder of its replacement.
 */
final class GoogleIdentityManager implements AutoCloseable {
    static final String SCHEMA = "dev.xenoid.google-identity/v1";
    private static final String GMS_PACKAGE = "com.google.android.gms";
    private static final String AD_ACTION =
            "com.google.android.gms.ads.identifier.service.START";
    private static final String AD_DESCRIPTOR =
            "com.google.android.gms.ads.identifier.internal.IAdvertisingIdService";
    private static final String EMPTY_AD_ID =
            "00000000-0000-0000-0000-000000000000";
    private static final Uri GSERVICES =
            Uri.parse("content://com.google.android.gsf.gservices");
    private static final String GSERVICES_CHANGED_ACTION =
            "com.google.gservices.intent.action.GSERVICES_CHANGED";
    private static final long BIND_TIMEOUT_MS = 10_000L;
    private static final long HEAL_INITIAL_BACKOFF_MS = 250L;
    private static final long HEAL_MAX_BACKOFF_MS = 10_000L;

    private final Context context;
    private final Object opLock = new Object();
    private final Object lock = new Object();
    private final ExecutorService healer;
    private BinderConnection activeConnection;
    private IBinder advertisingBinder;
    private boolean binding;
    private boolean closed;
    private boolean healScheduled;
    private boolean healRequested;
    private long generation;

    /**
     * One connection per bind attempt.  Callbacks carry the generation captured at
     * bind time and only mutate shared state while this connection is still the
     * active one for that generation, so a late disconnect/death callback from a
     * pre-activate connection cannot tear down its replacement.  Every registration
     * is released exactly once via release(), whichever path retires it.
     */
    private final class BinderConnection implements ServiceConnection, IBinder.DeathRecipient {
        private final long bindGeneration;
        private final java.util.concurrent.atomic.AtomicBoolean released =
                new java.util.concurrent.atomic.AtomicBoolean();

        BinderConnection(long bindGeneration) {
            this.bindGeneration = bindGeneration;
        }

        /** Exactly-once unregistration; safe from any callback or cleanup path. */
        void release() {
            if (released.compareAndSet(false, true)) {
                try {
                    context.unbindService(this);
                } catch (Throwable ignored) {
                }
            }
        }

        @Override public void onServiceConnected(ComponentName name, IBinder service) {
            IBinder usable = service;
            if (usable != null) {
                try {
                    usable.linkToDeath(this, 0);
                } catch (RemoteException died) {
                    usable = null;
                }
            }
            IBinder unlink = null;
            boolean dropConnection = false;
            boolean heal = false;
            synchronized (lock) {
                if (closed || activeConnection != this || bindGeneration != generation) {
                    // Superseded registration: never touch live state, but unlink
                    // the delivered binder and drop the connection we registered.
                    unlink = usable;
                    dropConnection = true;
                } else {
                    binding = false;
                    if (usable != null) {
                        // Success does not bump the generation: in-flight awaiters
                        // captured it and accept exactly this binder.
                        advertisingBinder = usable;
                    } else {
                        // Dead on arrival: invalidate awaiters, drop registration.
                        advertisingBinder = null;
                        generation++;
                        activeConnection = null;
                        dropConnection = true;
                        heal = true;
                    }
                    lock.notifyAll();
                }
            }
            if (unlink != null) {
                try {
                    unlink.unlinkToDeath(this, 0);
                } catch (Throwable ignored) {
                }
            }
            if (dropConnection) release();
            if (heal) scheduleHeal();
        }

        @Override public void onServiceDisconnected(ComponentName name) {
            lost(this);
        }

        @Override public void onBindingDied(ComponentName name) {
            lost(this);
        }

        @Override public void onNullBinding(ComponentName name) {
            lost(this);
        }

        @Override public void binderDied() {
            lost(this);
        }
    }

    GoogleIdentityManager(Context context) {
        this.context = context.getApplicationContext();
        healer = Executors.newSingleThreadExecutor(runnable -> {
            Thread thread = new Thread(runnable, "xenoid-google-identity");
            thread.setDaemon(true);
            return thread;
        });
        scheduleHeal();
    }

    Map<String, Object> status() {
        synchronized (opLock) {
            return observe(false, null);
        }
    }

    /**
     * Strictly observational read for host snapshots and preflight.  It never
     * binds/starts GMS, mutates rootd/profile/provider state, resets GAID/LAT, or
     * invalidates caches; no already-live binder means unavailable.  It proves the
     * exact pinned provider surface, reads the protected offline marker, and, when
     * the marker is present, fails unless the live GSF provider exposes that exact
     * value.  Thus an old nonempty marker can never make a provider-write-before-
     * marker crash window look committed.
     */
    Map<String, Object> inspect() {
        synchronized (opLock) {
            Map<String, Object> seedState = RootHelper.offlineGoogleIdentitySeeded();
            if (!Boolean.TRUE.equals(seedState.get("ok"))) {
                return failure(errorCode(seedState, "google_identity_unavailable"));
            }
            boolean offlineSeeded = Boolean.TRUE.equals(seedState.get("seeded"));
            String seededGsf = offlineSeeded
                    ? (String) seedState.get("gsfAndroidId") : null;
            Map<String, Object> surface = RootHelper.googleProviderSurface();
            if (!Boolean.TRUE.equals(surface.get("pinned"))) {
                return failure(errorCode(surface, "google_identity_unavailable"));
            }
            IBinder binder;
            synchronized (lock) {
                if (closed) return failure("google_identity_unavailable");
                binder = advertisingBinder;
            }
            if (binder == null || !binder.isBinderAlive() || !binder.pingBinder()) {
                return failure("google_identity_service_unavailable");
            }
            try {
                String advertisingId = readAdvertisingId(binder);
                if (!wellFormedAdvertisingId(advertisingId)
                        || offlineSeeded && EMPTY_AD_ID.equals(advertisingId)) {
                    return failure("google_identity_advertising_id_invalid");
                }
                String gsfAndroidId = readGsfAndroidId();
                boolean gsfPresent = validGsfAndroidId(gsfAndroidId);
                if (offlineSeeded && (!gsfPresent || !seededGsf.equals(gsfAndroidId))) {
                    return failure("google_identity_gsf_id_invalid");
                }
                return success(
                        advertisingId, gsfPresent ? gsfAndroidId : null, offlineSeeded);
            } catch (Throwable ignored) {
                return failure("google_identity_unavailable");
            }
        }
    }

    Map<String, Object> activate(String gsfAndroidId) {
        if (!validGsfAndroidId(gsfAndroidId)) {
            return failure("google_identity_target_invalid");
        }
        synchronized (opLock) {
            if (closed) {
                return failure("google_identity_unavailable");
            }
            Map<String, Object> surface = RootHelper.googleProviderSurface();
            if (!Boolean.TRUE.equals(surface.get("pinned"))) {
                return failure(errorCode(surface, "google_identity_unavailable"));
            }
            disconnect();
            Map<String, Object> seeded = RootHelper.seedGoogleIdentity(gsfAndroidId);
            if (!Boolean.TRUE.equals(seeded.get("ok"))) {
                return failure("google_identity_seed_failed");
            }
            try {
                IBinder binder = awaitAdvertisingBinder();
                if (binder == null) {
                    return failure("google_identity_service_unavailable");
                }
                String reset = resetAdvertisingId(binder);
                setAdTrackingLimitedGlobally(binder, false);
                String current = readAdvertisingId(binder);
                if (!validAdvertisingId(reset)
                        || !validAdvertisingId(current)
                        || !reset.equals(current)) {
                    return failure("google_identity_advertising_id_invalid");
                }
            } catch (Throwable ignored) {
                return failure("google_identity_unavailable");
            }
            return observe(true, gsfAndroidId);
        }
    }

    /**
     * Invalidates third-party Gservices client caches after a successful offline
     * seed: the provider cannot publish the direct gservices.db edit itself, so
     * already-running consumers would otherwise keep a stale android_id.  Check-in
     * stays disabled, so the broadcast cannot trigger any network check-in.
     */
    private boolean invalidateGoogleServicesCaches() {
        try {
            context.getContentResolver().notifyChange(GSERVICES, null);
        } catch (Throwable ignored) {
            return false;
        }
        Map<String,Object> broadcast = RootHelper.exec(
                "am broadcast -a " + GSERVICES_CHANGED_ACTION);
        return Boolean.TRUE.equals(broadcast.get("ok"));
    }

    private Map<String, Object> observe(boolean requireGsf, String expectedGsf) {
        if (closed) {
            return failure("google_identity_unavailable");
        }
        Map<String, Object> seedState = RootHelper.offlineGoogleIdentitySeeded();
        if (!Boolean.TRUE.equals(seedState.get("ok"))) {
            return failure(errorCode(seedState, "google_identity_unavailable"));
        }
        boolean offlineSeeded = Boolean.TRUE.equals(seedState.get("seeded"));
        String seededGsf = offlineSeeded
                ? (String) seedState.get("gsfAndroidId") : null;
        if (offlineSeeded) {
            Map<String, Object> surface = RootHelper.googleProviderSurface();
            if (!Boolean.TRUE.equals(surface.get("pinned"))) {
                return failure(errorCode(surface, "google_identity_unavailable"));
            }
        }
        try {
            IBinder binder = awaitAdvertisingBinder();
            if (binder == null) {
                return failure("google_identity_service_unavailable");
            }
            if (offlineSeeded) {
                // The exact provider guard ran before bind/start.  Only the
                // pinned MemoryAdvertisingIdConfiguration is mutated here.
                setAdTrackingLimitedGlobally(binder, false);
            }
            String advertisingId = readAdvertisingId(binder);
            if (!wellFormedAdvertisingId(advertisingId)
                    || offlineSeeded && EMPTY_AD_ID.equals(advertisingId)) {
                return failure("google_identity_advertising_id_invalid");
            }
            String gsfAndroidId = readGsfAndroidId();
            boolean gsfPresent = validGsfAndroidId(gsfAndroidId);
            if (requireGsf && (!gsfPresent || !expectedGsf.equals(gsfAndroidId))) {
                return failure("google_identity_gsf_id_invalid");
            }
            if (offlineSeeded
                    && (!gsfPresent || seededGsf == null || !seededGsf.equals(gsfAndroidId))) {
                return failure("google_identity_gsf_id_invalid");
            }
            Map<String, Object> result = success(
                    advertisingId, gsfPresent ? gsfAndroidId : null, offlineSeeded);
            if (offlineSeeded) {
                // Idempotent republication on every accepted offline-seeded read,
                // so a crash between seed and invalidation self-repairs on resume.
                if (!invalidateGoogleServicesCaches()) {
                    return failure("google_identity_cache_invalidation_failed");
                }
            }
            return result;
        } catch (Throwable ignored) {
            return failure("google_identity_unavailable");
        }
    }

    /** Runs one deduplicated retry loop after startup or binder/service/process loss. */
    private void scheduleHeal() {
        synchronized (lock) {
            if (closed) return;
            healRequested = true;
            if (healScheduled) return;
            healScheduled = true;
        }
        try {
            healer.execute(this::healUntilStable);
        } catch (Throwable ignored) {
            synchronized (lock) {
                healScheduled = false;
                healRequested = false;
            }
        }
    }

    private boolean gmsPackagePresent() {
        try {
            context.getPackageManager().getPackageInfo(GMS_PACKAGE, 0);
            return true;
        } catch (Throwable absent) {
            return false;
        }
    }

    private boolean retryableHealFailure(Map<String, Object> result) {
        if (Boolean.TRUE.equals(result.get("ok"))) return false;
        String error = errorCode(result, "google_identity_unavailable");
        if ("google_identity_service_unavailable".equals(error) && !gmsPackagePresent()) {
            // provider=none or a removed GMS package makes bindService fail
            // permanently; retrying would spin rootd/bind forever.
            return false;
        }
        return "google_identity_unavailable".equals(error)
                || "google_identity_service_unavailable".equals(error)
                || "google_identity_cache_invalidation_failed".equals(error);
    }

    private void healUntilStable() {
        long backoffMs = HEAL_INITIAL_BACKOFF_MS;
        while (true) {
            synchronized (lock) {
                if (closed) {
                    healScheduled = false;
                    healRequested = false;
                    return;
                }
                healRequested = false;
            }

            Map<String, Object> result;
            try {
                result = status();
            } catch (Throwable ignored) {
                result = failure("google_identity_unavailable");
            }
            if (retryableHealFailure(result)) {
                try {
                    Thread.sleep(backoffMs);
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    synchronized (lock) {
                        healScheduled = false;
                        healRequested = false;
                    }
                    return;
                }
                backoffMs = Math.min(HEAL_MAX_BACKOFF_MS, backoffMs * 2L);
                continue;
            }

            synchronized (lock) {
                if (closed) {
                    healScheduled = false;
                    healRequested = false;
                    return;
                }
                if (healRequested) {
                    backoffMs = HEAL_INITIAL_BACKOFF_MS;
                    continue;
                }
                healScheduled = false;
                return;
            }
        }
    }

    /**
     * Invalidates live binder state only when the loss came from the active
     * connection, then unregisters it (onBindingDied requires an explicit unbind
     * before any rebind, and process death must not leak the registration).
     */
    private void lost(BinderConnection source) {
        BinderConnection stale = null;
        synchronized (lock) {
            if (closed || activeConnection != source
                    || source.bindGeneration != generation) {
                return;
            }
            if (advertisingBinder != null) {
                try {
                    advertisingBinder.unlinkToDeath(source, 0);
                } catch (Throwable ignored) {
                }
                advertisingBinder = null;
            }
            binding = false;
            generation++;
            stale = activeConnection;
            activeConnection = null;
            lock.notifyAll();
        }
        if (stale != null) stale.release();
        scheduleHeal();
    }

    private IBinder awaitAdvertisingBinder() throws InterruptedException {
        long deadline = android.os.SystemClock.elapsedRealtime() + BIND_TIMEOUT_MS;
        BinderConnection expired = null;
        IBinder result;
        synchronized (lock) {
            if (closed) return null;
            long expected = generation;
            if (advertisingBinder == null && !binding) {
                BinderConnection candidate = new BinderConnection(generation);
                Intent intent = new Intent(AD_ACTION).setPackage(GMS_PACKAGE);
                boolean requested;
                try {
                    requested = context.bindService(
                            intent, candidate, Context.BIND_AUTO_CREATE);
                } catch (Throwable rejected) {
                    requested = false;
                }
                if (!requested) return null;
                activeConnection = candidate;
                binding = true;
            }
            while (!closed && advertisingBinder == null && expected == generation) {
                long remaining = deadline - android.os.SystemClock.elapsedRealtime();
                if (remaining <= 0) break;
                lock.wait(remaining);
            }
            result = closed || expected != generation ? null : advertisingBinder;
            if (result == null && binding && activeConnection != null) {
                // Never strand a registered connection with binding=true: every
                // later caller would skip bindService and stall to the deadline.
                expired = activeConnection;
                activeConnection = null;
                binding = false;
                generation++;
            }
        }
        if (expired != null) expired.release();
        return result;
    }

    private void setAdTrackingLimitedGlobally(IBinder binder, boolean limited)
            throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AD_DESCRIPTOR);
            data.writeString(context.getPackageName());
            data.writeInt(limited ? 1 : 0);
            if (!binder.transact(4, data, reply, 0)) throw new Exception();
            reply.readException();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private String resetAdvertisingId(IBinder binder) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AD_DESCRIPTOR);
            data.writeString(context.getPackageName());
            if (!binder.transact(3, data, reply, 0)) throw new Exception();
            reply.readException();
            return reply.readString();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private static String readAdvertisingId(IBinder binder) throws Exception {
        Parcel data = Parcel.obtain();
        Parcel reply = Parcel.obtain();
        try {
            data.writeInterfaceToken(AD_DESCRIPTOR);
            if (!binder.transact(1, data, reply, 0)) throw new Exception();
            reply.readException();
            return reply.readString();
        } finally {
            reply.recycle();
            data.recycle();
        }
    }

    private String readGsfAndroidId() {
        try (Cursor cursor = context.getContentResolver().query(
                GSERVICES, null, null, new String[]{"android_id"}, null)) {
            if (cursor == null || !cursor.moveToFirst() || cursor.getColumnCount() < 2) {
                return null;
            }
            return cursor.getString(1);
        } catch (Throwable ignored) {
            return null;
        }
    }

    private static boolean wellFormedAdvertisingId(String value) {
        if (value == null) return false;
        try {
            return value.equals(UUID.fromString(value).toString());
        } catch (IllegalArgumentException ignored) {
            return false;
        }
    }

    private static boolean validAdvertisingId(String value) {
        return wellFormedAdvertisingId(value) && !EMPTY_AD_ID.equals(value);
    }

    private static boolean validGsfAndroidId(String value) {
        if (value == null || !value.matches("[1-9][0-9]{0,18}")) return false;
        try {
            long parsed = Long.parseLong(value);
            return parsed > 0;
        } catch (NumberFormatException ignored) {
            return false;
        }
    }

    private static String sha256(String value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256")
                .digest(value.getBytes(StandardCharsets.US_ASCII));
        StringBuilder result = new StringBuilder(64);
        for (byte item : digest) result.append(String.format("%02x", item & 0xff));
        return result.toString();
    }

    private static String errorCode(Map<String, Object> value, String fallback) {
        Object candidate = value == null ? null : value.get("error");
        return candidate instanceof String
                && ((String) candidate).matches("[a-z][a-z0-9_]{0,63}")
                ? (String) candidate : fallback;
    }

    private static Map<String, Object> success(
            String advertisingId, String gsfAndroidId, boolean offlineSeeded)
            throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", true);
        result.put("schema", SCHEMA);
        result.put("advertisingIdSha256", sha256(advertisingId));
        result.put("gsfAndroidIdPresent", gsfAndroidId != null);
        result.put("gsfAndroidIdSha256", gsfAndroidId == null ? null : sha256(gsfAndroidId));
        result.put("offlineSeeded", offlineSeeded);
        return result;
    }

    private static Map<String, Object> failure(String code) {
        Map<String, Object> result = new LinkedHashMap<>();
        result.put("ok", false);
        result.put("schema", SCHEMA);
        result.put("error", code);
        return result;
    }

    private void disconnect() {
        BinderConnection stale;
        synchronized (lock) {
            generation++;
            if (advertisingBinder != null && activeConnection != null) {
                try {
                    advertisingBinder.unlinkToDeath(activeConnection, 0);
                } catch (Throwable ignored) {
                }
            }
            advertisingBinder = null;
            binding = false;
            stale = activeConnection;
            activeConnection = null;
            lock.notifyAll();
        }
        if (stale != null) stale.release();
    }

    @Override public void close() {
        synchronized (lock) {
            if (closed) return;
            closed = true;
        }
        healer.shutdownNow();
        disconnect();
    }
}
