package dev.xenoid.daemon;

import android.content.ContentResolver;
import android.content.ContentValues;
import android.content.Context;
import android.provider.Settings;
import android.provider.Telephony;
import android.database.Cursor;
import android.util.Base64;

import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.FileOutputStream;
import java.nio.ByteBuffer;
import java.nio.ByteOrder;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.StandardCopyOption;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Locale;
import java.util.Map;
import java.util.Set;
import java.util.TimeZone;

/** Owns the protected location radio profile and its framework-visible side effects. */
final class LocationIdentityManager {
    private static final String PROFILE_SCHEMA = "dev.xenoid.cellular-profile/v2";
    private static final String STATE_SCHEMA = "dev.xenoid.android-location/v1";
    private static final String STAGE_SCHEMA = "dev.xenoid.location-stage/v1";
    private static final byte[] PROFILE_MAGIC = "XENOID_PROFILE_V1\0".getBytes(StandardCharsets.US_ASCII);
    private static final int PROFILE_FIELDS = 21;
    private static final int MAX_PROFILE_BYTES = 64 * 1024;
    private static final String PROFILE_PATH = "/data/vendor/radio/xenoid/profile.v1";
    private static final String STATE_NAME = "location-identity.json";
    private static final String STAGE_NAME = "location-profile.stage";
    private static final String LEGACY_STATE_NAME = "regional-identity.json";
    // Total surface-read budget for one verify call: safely below the host's
    // 150s location_verify timeout so daemon state never outlives a failed RPC.
    // Post-wipe boots need most of this for APN restore and data-call bring-up.
    private static final long VERIFY_SURFACE_BUDGET_MS = 100000L;
    private static final long CELL_INFO_CALLBACK_TIMEOUT_MS = 4000L;
    private static final String[] EXACT_PROFILE_KEYS = {
            "schema", "slot", "sim", "carrier", "operator", "cell", "dataCall",
            "locale", "timezone", "callingCode", "locationKey", "identityDigest"
    };

    private final Context context;
    private final File stateFile;

    LocationIdentityManager(Context context) {
        this.context = context.getApplicationContext();
        this.stateFile = new File(context.getNoBackupFilesDir(), STATE_NAME);
        try {
            Map<String, Object> state = loadState();
            if (state != null) purgeLegacyState();
        } catch (Exception ignored) {
            android.util.Log.e("xenoid-daemon", "location identity initialization failed");
        }
    }

    /** Removes product-owned pre-location state once the new identity exists. */
    private void purgeLegacyState() {
        File legacy = new File(context.getNoBackupFilesDir(), LEGACY_STATE_NAME);
        if (legacy.exists() && !legacy.delete()) {
            android.util.Log.e("xenoid-daemon", "legacy regional state cleanup failed");
        }
        File legacyStage = new File(context.getNoBackupFilesDir(), "regional-profile.stage");
        if (legacyStage.exists() && !legacyStage.delete()) {
            android.util.Log.e("xenoid-daemon", "legacy regional stage cleanup failed");
        }
        File legacyTmp = new File(context.getNoBackupFilesDir(), ".regional-identity.tmp");
        if (legacyTmp.exists() && !legacyTmp.delete()) {
            android.util.Log.e("xenoid-daemon", "legacy regional temp cleanup failed");
        }
        RootHelper.purgeLegacyRegionalState();
    }

    synchronized void restoreDataPlane() throws Exception {
        Map<String, Object> state = loadState();
        if (state == null) return;
        String numeric = bounded(string(state, "operatorNumeric"), 5, 6);
        if (!numeric.matches("[0-9]{5,6}")) throw new IllegalStateException("location_state_invalid");
        String name = bounded(string(state, "carrier"), 1, 128);
        String apn = bounded(string(state, "apn"), 1, 128);
        Exception failure = null;
        for (int attempt = 0; attempt < 20; attempt++) {
            try {
                configureApn(name, numeric.substring(0, 3), numeric.substring(3), apn);
                if (apnPresent(numeric, apn)) return;
                failure = new IllegalStateException("location_apn_verify_failed");
            } catch (Exception retryable) {
                failure = retryable;
            }
            try {
                Thread.sleep(500);
            } catch (InterruptedException interrupted) {
                Thread.currentThread().interrupt();
                throw interrupted;
            }
        }
        throw new IllegalStateException("location_apn_restore_failed", failure);
    }

    synchronized Map<String, Object> status() throws Exception {
        Map<String, Object> state = loadState();
        if (state == null) return map("ok", true, "state", "absent");
        Map<String, Object> result = publicState(state);
        result.put("ok", true);
        return result;
    }

    synchronized Map<String, Object> stage(Map<String, Object> request) throws Exception {
        requireKeys(request, "schema", "profile", "encodedProfile", "profileDigest",
                "locationKey", "runtimeEpoch");
        if (!STAGE_SCHEMA.equals(string(request, "schema"))) {
            throw new IllegalArgumentException("location_request_invalid");
        }
        Map<String, Object> profile = object(request, "profile");
        validateProfile(profile);
        String profileDigest = hex64(string(request, "profileDigest"));
        String locationKey = bounded(string(request, "locationKey"), 4, 192);
        if (!profileDigest.equals(string(profile, "identityDigest"))
                || !locationKey.equals(string(profile, "locationKey"))) {
            throw new IllegalArgumentException("location_profile_mismatch");
        }
        Map<String, Object> digestInput = new LinkedHashMap<>(profile);
        digestInput.remove("identityDigest");
        if (!profileDigest.equals(sha256(canonical(digestInput)))) {
            throw new IllegalArgumentException("location_profile_digest_mismatch");
        }
        byte[] encoded;
        try {
            encoded = Base64.decode(string(request, "encodedProfile"), Base64.NO_WRAP);
        } catch (IllegalArgumentException error) {
            throw new IllegalArgumentException("location_profile_encoding_invalid");
        }
        try {
            validateEncodedProfile(encoded, profile);
            File staging = new File(context.getNoBackupFilesDir(), STAGE_NAME);
            atomicWrite(staging, encoded);
            try {
                if (!RootHelper.publishLocationProfile(staging, PROFILE_PATH, encoded.length,
                        sha256(encoded))) {
                    throw new IllegalStateException("location_profile_publish_failed");
                }
            } finally {
                staging.delete();
            }
        } finally {
            java.util.Arrays.fill(encoded, (byte) 0);
        }

        Map<String, Object> carrier = object(profile, "carrier");
        Map<String, Object> cell = object(profile, "cell");
        configureApn(carrier);
        setLocationProperties(profile, cell, profileDigest);
        boolean provisionedBefore = provisioned();
        convergeProvisioning();
        Map<String, Object> previous = loadState();
        Map<String, Object> imeBefore = imeSnapshot();
        boolean manageIme = !provisionedBefore || imeStillManaged(previous, imeBefore);

        Map<String, Object> state = new LinkedHashMap<>();
        state.put("schema", STATE_SCHEMA);
        state.put("state", "staged");
        state.put("locationKey", locationKey);
        state.put("profileDigest", profileDigest);
        state.put("runtimeEpoch", bounded(string(request, "runtimeEpoch"), 1, 192));
        state.put("countryCode", string(object(profile, "operator"), "isoCountry").toUpperCase(Locale.ROOT));
        state.put("timezone", string(profile, "timezone"));
        state.put("locale", new ArrayList<>(array(profile, "locale")));
        state.put("callingCode", string(profile, "callingCode"));
        state.put("carrier", string(carrier, "name"));
        state.put("operatorNumeric", string(object(profile, "operator"), "numeric"));
        state.put("apn", string(carrier, "apn"));
        state.put("band", strictLong(cell, "band", 1));
        state.put("earfcn", strictLong(cell, "earfcn", 0));
        state.put("bandwidthKhz", strictLong(cell, "bandwidthKhz", 1));
        state.put("tac", strictLong(cell, "tac", 1));
        state.put("eci", strictLong(cell, "eci", 1));
        state.put("pci", strictLong(cell, "pci", 0));
        state.put("imsi", mask(string(object(profile, "sim"), "imsi")));
        state.put("iccid", mask(string(object(profile, "sim"), "iccid")));
        state.put("msisdn", mask(string(object(profile, "sim"), "msisdn")));
        state.put("imeManaged", manageIme);
        state.put("imeBefore", imeBefore);
        state.put("imeAfter", previous == null ? null : previous.get("imeAfter"));
        saveState(state);
        Map<String, Object> result = publicState(state);
        result.put("ok", true);
        result.put("recreateRequired", true);
        return result;
    }

    synchronized Map<String, Object> verify(Map<String, Object> request) throws Exception {
        requireKeys(request, "profileDigest", "runtimeEpoch");
        Map<String, Object> state = loadState();
        if (state == null) throw new IllegalStateException("location_state_missing");
        String digest = hex64(string(request, "profileDigest"));
        if (!digest.equals(string(state, "profileDigest"))) {
            throw new IllegalStateException("location_identity_split_brain");
        }
        convergeProvisioning();
        String locale = firstLocale(state);
        String timezone = string(state, "timezone");
        String operatorNumeric = string(state, "operatorNumeric");
        // Radio/framework surfaces settle after boot; grant them a bounded
        // window that must stay well under the host's 120s verify timeout, or
        // the host fails the call while the daemon still promotes the state.
        long deadline = android.os.SystemClock.elapsedRealtime() + VERIFY_SURFACE_BUDGET_MS;
        Exception lastFailure = new IllegalStateException("location_identity_unverified");
        while (true) {
            try {
                ensureApnConverged(state);
                verifySurfaces(state, digest, locale, timezone, operatorNumeric);
                lastFailure = null;
                break;
            } catch (IllegalStateException failure) {
                lastFailure = failure;
                long remaining = deadline - android.os.SystemClock.elapsedRealtime();
                if (remaining <= 0) break;
                try {
                    Thread.sleep(Math.min(1500, remaining));
                } catch (InterruptedException interrupted) {
                    Thread.currentThread().interrupt();
                    throw interrupted;
                }
            }
        }
        if (lastFailure != null) throw lastFailure;
        if (Boolean.TRUE.equals(state.get("imeManaged"))) {
            Map<String, Object> current = imeSnapshot();
            Object expected = state.get("imeAfter") != null ? state.get("imeAfter") : state.get("imeBefore");
            if (sameJson(current, expected)) {
                Map<String, Object> reset = RootHelper.execRootd("ime reset >/dev/null");
                if (!Boolean.TRUE.equals(reset.get("ok"))) {
                    throw new IllegalStateException("location_ime_reset_failed");
                }
                state.put("imeAfter", imeSnapshot());
            } else {
                state.put("imeManaged", false);
            }
        }
        state.put("state", "active");
        state.put("runtimeEpoch", bounded(string(request, "runtimeEpoch"), 1, 192));
        saveState(state);
        purgeLegacyState();
        Map<String, Object> result = publicState(state);
        result.put("ok", true);
        result.put("verified", true);
        result.put("localeVerified", true);
        result.put("timezoneVerified", true);
        result.put("radioVerified", true);
        result.put("provisioningVerified", true);
        return result;
    }

    private void validateProfile(Map<String, Object> profile) {
        requireKeys(profile, EXACT_PROFILE_KEYS);
        if (!PROFILE_SCHEMA.equals(string(profile, "schema"))) throw invalidProfile();
        Map<String, Object> slot = object(profile, "slot");
        requireKeys(slot, "slotId", "portId", "logicalSlotIndex", "present", "ready", "embedded");
        if (strictLong(slot, "slotId", 0) != 0 || strictLong(slot, "portId", 0) != 0
                || strictLong(slot, "logicalSlotIndex", 0) != 0
                || !Boolean.TRUE.equals(slot.get("present")) || !Boolean.TRUE.equals(slot.get("ready"))
                || !Boolean.FALSE.equals(slot.get("embedded"))) throw invalidProfile();
        Map<String, Object> sim = object(profile, "sim");
        requireKeys(sim, "imsi", "iccid", "msisdn", "spn", "gid1", "ad", "mncLength");
        String imsi = digits(string(sim, "imsi"), 15, 15);
        digits(string(sim, "iccid"), 20, 20);
        String msisdn = string(sim, "msisdn");
        if (!msisdn.matches("\\+[1-9][0-9]{7,14}")) throw invalidProfile();
        Map<String, Object> carrier = object(profile, "carrier");
        requireKeys(carrier, "name", "mcc", "mnc", "apn", "bands");
        String mcc = digits(string(carrier, "mcc"), 3, 3);
        String mnc = digits(string(carrier, "mnc"), 2, 3);
        if (!imsi.startsWith(mcc + mnc) || strictLong(sim, "mncLength", 2) != mnc.length()) throw invalidProfile();
        bounded(string(carrier, "name"), 1, 128);
        bounded(string(carrier, "apn"), 1, 128);
        List<Object> bands = array(carrier, "bands");
        if (bands.isEmpty()) throw invalidProfile();
        Map<String, Object> operator = object(profile, "operator");
        requireKeys(operator, "alphaLong", "alphaShort", "numeric", "isoCountry", "isoNetwork", "roaming");
        if (!(mcc + mnc).equals(string(operator, "numeric"))
                || !string(operator, "isoCountry").matches("[a-z]{2}")
                || !string(operator, "isoCountry").equals(string(operator, "isoNetwork"))
                || !Boolean.FALSE.equals(operator.get("roaming"))) throw invalidProfile();
        String callingCode = string(profile, "callingCode");
        if (!callingCode.matches("\\+[1-9][0-9]{0,3}") || !msisdn.startsWith(callingCode)) {
            throw invalidProfile();
        }
        Map<String, Object> cell = object(profile, "cell");
        requireKeys(cell, "technology", "tac", "eci", "pci", "earfcn", "band", "bandwidthKhz",
                "rsrp", "rsrq", "rssnr", "cqi", "timingAdvance");
        if (!"LTE".equals(string(cell, "technology"))) throw invalidProfile();
        range(strictLong(cell, "tac", 1), 1, 65535); range(strictLong(cell, "eci", 1), 1, 268435455);
        range(strictLong(cell, "pci", 0), 0, 503); range(strictLong(cell, "earfcn", 0), 0, 262143);
        long band = strictLong(cell, "band", 1); range(band, 1, 256);
        if (!bands.contains(band) && !bands.contains((int) band)) throw invalidProfile();
        if (strictLong(cell, "bandwidthKhz", 1) != 10000) throw invalidProfile();
        range(strictLong(cell, "rsrp", -140), -140, -44); range(strictLong(cell, "rsrq", -20), -20, -3);
        range(strictLong(cell, "rssnr", 30), 30, 200); range(strictLong(cell, "cqi", 0), 0, 15);
        range(strictLong(cell, "timingAdvance", 0), 0, 63);
        Map<String, Object> dataCall = object(profile, "dataCall");
        requireKeys(dataCall, "iface", "state", "protocol", "addresses", "gateways", "dnses", "mtu");
        if (!"rmnet_data0".equals(string(dataCall, "iface")) || !"CONNECTED".equals(string(dataCall, "state"))
                || !"IPV4V6".equals(string(dataCall, "protocol")) || strictLong(dataCall, "mtu", 1280) != 1500) {
            throw invalidProfile();
        }
        array(dataCall, "addresses"); array(dataCall, "gateways"); array(dataCall, "dnses");
        List<Object> locales = array(profile, "locale");
        if (locales.isEmpty() || locales.size() > 16) throw invalidProfile();
        for (Object item : locales) if (!(item instanceof String) || !((String) item).matches("[A-Za-z]{2,3}(-[A-Za-z0-9]{2,8})*")) throw invalidProfile();
        String timezone = bounded(string(profile, "timezone"), 1, 128);
        String locationKey = bounded(string(profile, "locationKey"), 4, 192);
        String expectedKey = string(operator, "isoCountry").toUpperCase(Locale.ROOT) + "/" + timezone;
        if (!locationKey.equals(expectedKey)) throw invalidProfile();
        hex64(string(profile, "identityDigest"));
    }

    private static void validateEncodedProfile(byte[] encoded, Map<String, Object> profile) throws Exception {
        if (encoded.length <= PROFILE_MAGIC.length + 8 + 32 || encoded.length > MAX_PROFILE_BYTES) throw invalidProfile();
        for (int i = 0; i < PROFILE_MAGIC.length; i++) if (encoded[i] != PROFILE_MAGIC[i]) throw invalidProfile();
        ByteBuffer buffer = ByteBuffer.wrap(encoded).order(ByteOrder.BIG_ENDIAN);
        buffer.position(PROFILE_MAGIC.length);
        if (buffer.getInt() != 1 || buffer.getInt() != PROFILE_FIELDS) throw invalidProfile();
        int payloadStart = buffer.position();
        int payloadEnd = encoded.length - 32;
        MessageDigest sha = MessageDigest.getInstance("SHA-256");
        byte[] actual = sha.digest(java.util.Arrays.copyOfRange(encoded, payloadStart, payloadEnd));
        byte[] expected = java.util.Arrays.copyOfRange(encoded, payloadEnd, encoded.length);
        if (!MessageDigest.isEqual(actual, expected)) throw invalidProfile();
        int prior = 0;
        Map<Integer, byte[]> fields = new LinkedHashMap<>();
        while (buffer.position() < payloadEnd) {
            if (payloadEnd - buffer.position() < 6) throw invalidProfile();
            int id = buffer.getShort() & 0xffff;
            int length = buffer.getInt();
            if (id <= prior || id < 1 || id > PROFILE_FIELDS || length <= 0 || length > 8192
                    || length > payloadEnd - buffer.position()) throw invalidProfile();
            byte[] value = new byte[length]; buffer.get(value); fields.put(id, value); prior = id;
        }
        if (buffer.position() != payloadEnd || fields.size() != PROFILE_FIELDS) throw invalidProfile();
        Map<String, Object> sim = object(profile, "sim");
        Map<String, Object> carrier = object(profile, "carrier");
        Map<String, Object> cell = object(profile, "cell");
        assertField(fields, 1, string(carrier, "mcc")); assertField(fields, 2, string(carrier, "mnc"));
        assertField(fields, 3, string(sim, "imsi")); assertField(fields, 4, string(sim, "iccid"));
        assertField(fields, 5, string(sim, "msisdn")); assertField(fields, 6, string(carrier, "name"));
        assertField(fields, 7, string(carrier, "apn"));
        assertInt(fields, 8, strictLong(cell, "tac", 1)); assertInt(fields, 9, strictLong(cell, "eci", 1));
        assertInt(fields, 10, strictLong(cell, "pci", 0)); assertInt(fields, 11, strictLong(cell, "earfcn", 0));
        assertInt(fields, 12, strictLong(cell, "band", 1)); assertInt(fields, 13, strictLong(cell, "rsrp", -140));
        assertInt(fields, 14, strictLong(cell, "rsrq", -20));
        assertInt(fields, 15, strictLong(cell, "rssnr", 30));
        assertInt(fields, 16, strictLong(cell, "cqi", 0)); assertInt(fields, 17, strictLong(cell, "timingAdvance", 0));
        List<Object> locales = array(profile, "locale");
        List<String> localeStrings = new ArrayList<>(); for (Object value : locales) localeStrings.add((String) value);
        assertField(fields, 18, android.text.TextUtils.join(",", localeStrings));
        assertField(fields, 19, string(profile, "timezone")); assertField(fields, 20, string(profile, "identityDigest"));
        assertInt(fields, 21, strictLong(cell, "bandwidthKhz", 1));
    }

    /**
     * The carriers table lives in per-boot-wiped app data, so the APN written
     * before a recreate is always lost; re-publish until the provider accepts
     * it instead of passively waiting for a row that never returns.
     */
    private void ensureApnConverged(Map<String, Object> state) {
        String numeric = string(state, "operatorNumeric");
        String apn = string(state, "apn");
        if (apnPresent(numeric, apn)) return;
        try {
            configureApn(string(state, "carrier"), numeric.substring(0, 3), numeric.substring(3), apn);
        } catch (Exception ignored) {
            // TelephonyProvider may still be starting; the verify loop retries.
        }
        if (!apnPresent(numeric, apn)) {
            throw new IllegalStateException("location_apn_restore_failed");
        }
    }

    private void verifySurfaces(Map<String, Object> state, String digest, String locale,
            String timezone, String operatorNumeric) {
        String propertyDigest = getProperty("persist.xenoid.radio.profile_digest");
        String propertyLocale = getProperty("persist.sys.locale");
        String propertyTimezone = getProperty("persist.sys.timezone");
        String propertyOperator = getProperty("gsm.operator.numeric");
        boolean localeOk = locale.equals(Locale.getDefault().toLanguageTag())
                && !context.getResources().getConfiguration().getLocales().isEmpty()
                && locale.equals(context.getResources().getConfiguration().getLocales().get(0).toLanguageTag());
        boolean timezoneOk = timezone.equals(TimeZone.getDefault().getID());
        boolean radioOk = digest.equals(propertyDigest)
                && operatorNumeric.equals(propertyOperator)
                && apnPresent(string(state, "operatorNumeric"), string(state, "apn"));
        boolean provisioningOk = provisioned();
        boolean surfacesOk = radioSurfacesOk(state);
        if (!digest.equals(propertyDigest) || !locale.equals(propertyLocale)
                || !timezone.equals(propertyTimezone) || !localeOk || !timezoneOk
                || !radioOk || !provisioningOk || !surfacesOk) {
            android.util.Log.e("xenoid-daemon", "location verify pending:"
                    + " digestOk=" + digest.equals(propertyDigest)
                    + " localePropOk=" + locale.equals(propertyLocale)
                    + " timezonePropOk=" + timezone.equals(propertyTimezone)
                    + " localeOk=" + localeOk + " timezoneOk=" + timezoneOk
                    + " radioOk=" + radioOk + " provisioningOk=" + provisioningOk
                    + " surfacesOk=" + surfacesOk);
            throw new IllegalStateException("location_identity_unverified");
        }
    }

    /** Read-back of framework telephony/subscription/cell/connectivity surfaces. */
    private boolean radioSurfacesOk(Map<String, Object> state) {
        String step = "init";
        try {
            String numeric = string(state, "operatorNumeric");
            String mcc = numeric.substring(0, 3);
            String mnc = numeric.substring(3);
            String iso = string(state, "countryCode").toLowerCase(Locale.ROOT);
            android.telephony.TelephonyManager telephony =
                    (android.telephony.TelephonyManager) context.getSystemService(Context.TELEPHONY_SERVICE);
            if (telephony == null) { step = "telephony"; return logSurfaceFail(step); }
            if (telephony.getSimState() != android.telephony.TelephonyManager.SIM_STATE_READY) { step = "simState"; return logSurfaceFail(step); }
            if (telephony.getActiveModemCount() != 1) { step = "modemCount:" + telephony.getActiveModemCount(); return logSurfaceFail(step); }
            if (!numeric.equals(telephony.getSimOperator())) { step = "simOperator:" + telephony.getSimOperator(); return logSurfaceFail(step); }
            if (!numeric.equals(telephony.getNetworkOperator())) { step = "networkOperator:" + telephony.getNetworkOperator(); return logSurfaceFail(step); }
            if (!iso.equals(telephony.getSimCountryIso())) { step = "simCountryIso"; return logSurfaceFail(step); }
            if (!iso.equals(telephony.getNetworkCountryIso())) { step = "networkCountryIso"; return logSurfaceFail(step); }
            if (telephony.getVoiceNetworkType() != android.telephony.TelephonyManager.NETWORK_TYPE_LTE
                    || telephony.getDataNetworkType() != android.telephony.TelephonyManager.NETWORK_TYPE_LTE) {
                step = "networkType:" + telephony.getVoiceNetworkType() + "/" + telephony.getDataNetworkType();
                return logSurfaceFail(step);
            }
            android.telephony.SubscriptionManager subscriptions =
                    (android.telephony.SubscriptionManager) context.getSystemService(Context.TELEPHONY_SUBSCRIPTION_SERVICE);
            List<android.telephony.SubscriptionInfo> active = subscriptions == null
                    ? null : subscriptions.getActiveSubscriptionInfoList();
            if (active == null || active.size() != 1) { step = "subscriptions:" + (active == null ? "null" : active.size()); return logSurfaceFail(step); }
            android.telephony.SubscriptionInfo info = active.get(0);
            if (info.getSimSlotIndex() != 0 || info.getSubscriptionId() <= 0) { step = "subscriptionSlot"; return logSurfaceFail(step); }
            if (!mcc.equals(info.getMccString()) || !mnc.equals(info.getMncString())) { step = "subscriptionPlmn:" + info.getMccString() + "/" + info.getMncString(); return logSurfaceFail(step); }
            if (!iso.equals(String.valueOf(info.getCountryIso()).toLowerCase(Locale.ROOT))) { step = "subscriptionIso:" + info.getCountryIso(); return logSurfaceFail(step); }
            List<android.telephony.CellInfo> cells = telephony.getAllCellInfo();
            if (cells == null || cells.isEmpty()) {
                // The framework cell-info cache is only filled on demand; actively
                // request one update instead of reading a possibly empty cache.
                cells = requestFreshCellInfo(telephony, 15000);
            }
            if (cells == null) { step = "cellsNull"; return logSurfaceFail(step); }
            android.telephony.CellInfoLte registered = null;
            int registeredCount = 0;
            for (android.telephony.CellInfo cell : cells) {
                if (cell instanceof android.telephony.CellInfoLte && cell.isRegistered()) {
                    registered = (android.telephony.CellInfoLte) cell;
                    registeredCount++;
                }
            }
            if (registeredCount != 1 || registered == null) { step = "registeredCells:" + registeredCount + "/" + cells.size(); return logSurfaceFail(step); }
            android.telephony.CellIdentityLte identity = registered.getCellIdentity();
            if (!mcc.equals(identity.getMccString()) || !mnc.equals(identity.getMncString())) { step = "cellPlmn:" + identity.getMccString() + "/" + identity.getMncString(); return logSurfaceFail(step); }
            if (identity.getTac() != longState(state, "tac")
                    || identity.getCi() != longState(state, "eci")
                    || identity.getPci() != longState(state, "pci")
                    || identity.getEarfcn() != (int) longState(state, "earfcn")
                    || identity.getBandwidth() != (int) longState(state, "bandwidthKhz")) {
                step = "cellFields:" + identity.getTac() + "/" + identity.getCi() + "/" + identity.getPci()
                        + "/" + identity.getEarfcn() + "/" + identity.getBandwidth()
                        + " want " + longState(state, "tac") + "/" + longState(state, "eci") + "/"
                        + longState(state, "pci") + "/" + longState(state, "earfcn") + "/" + longState(state, "bandwidthKhz");
                return logSurfaceFail(step);
            }
            // The image-shipped telephony bridge derives bands from EARFCN for
            // the legacy HIDL conversion; require both the derivation and the
            // app-visible bands array to agree with the staged profile. The
            // ranges mirror the 3GPP table the bridge uses (the AOSP helper is
            // not part of the public SDK).
            int derivedBand = bandForEarfcn(identity.getEarfcn());
            if (derivedBand != (int) longState(state, "band")) { step = "derivedBand:" + derivedBand; return logSurfaceFail(step); }
            boolean bandFound = false;
            for (int band : identity.getBands()) {
                if (band == derivedBand) bandFound = true;
            }
            if (!bandFound) { step = "bandsEmpty"; return logSurfaceFail(step); }
            android.net.ConnectivityManager connectivity =
                    (android.net.ConnectivityManager) context.getSystemService(Context.CONNECTIVITY_SERVICE);
            if (connectivity == null) { step = "connectivity"; return logSurfaceFail(step); }
            android.net.Network activeNetwork = connectivity.getActiveNetwork();
            android.net.NetworkCapabilities activeCapabilities = activeNetwork == null
                    ? null : connectivity.getNetworkCapabilities(activeNetwork);
            if (activeCapabilities == null
                    || !activeCapabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_CELLULAR)
                    || activeCapabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) {
                step = "activeTransport";
                return logSurfaceFail(step);
            }
            android.net.LinkProperties link = connectivity.getLinkProperties(activeNetwork);
            if (link == null || !"rmnet_data0".equals(link.getInterfaceName())) { step = "linkIface:" + (link == null ? "null" : link.getInterfaceName()); return logSurfaceFail(step); }
            for (android.net.Network network : connectivity.getAllNetworks()) {
                android.net.NetworkCapabilities capabilities = connectivity.getNetworkCapabilities(network);
                if (capabilities != null
                        && capabilities.hasTransport(android.net.NetworkCapabilities.TRANSPORT_ETHERNET)) {
                    step = "ethernetPresent";
                    return logSurfaceFail(step);
                }
            }
            return true;
        } catch (Exception failure) {
            android.util.Log.e("xenoid-daemon", "location surface verification failed at " + step, failure);
            return false;
        }
    }

    private static boolean logSurfaceFail(String step) {
        android.util.Log.e("xenoid-daemon", "location surface check failed: " + step);
        return false;
    }

    private final java.util.concurrent.ExecutorService cellInfoExecutor =
            java.util.concurrent.Executors.newSingleThreadExecutor(runnable -> {
                Thread thread = new Thread(runnable, "location-cell-info");
                thread.setDaemon(true);
                return thread;
            });

    private List<android.telephony.CellInfo> requestFreshCellInfo(
            android.telephony.TelephonyManager telephony, long timeoutMs) {
        java.util.concurrent.CountDownLatch latch = new java.util.concurrent.CountDownLatch(1);
        java.util.concurrent.atomic.AtomicReference<List<android.telephony.CellInfo>> result =
                new java.util.concurrent.atomic.AtomicReference<>();
        try {
            // A dedicated executor is required: verify blocks on the latch, so a
            // main-looper callback could never run and would self-deadlock.
            telephony.requestCellInfoUpdate(cellInfoExecutor,
                    new android.telephony.TelephonyManager.CellInfoCallback() {
                        @Override public void onCellInfo(List<android.telephony.CellInfo> values) {
                            result.set(values);
                            latch.countDown();
                        }
                        @Override public void onError(int errorCode, Throwable detail) {
                            android.util.Log.e("xenoid-daemon",
                                    "location cell-info request error " + errorCode, detail);
                            latch.countDown();
                        }
                    });
            latch.await(timeoutMs, java.util.concurrent.TimeUnit.MILLISECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
        } catch (Exception failure) {
            android.util.Log.e("xenoid-daemon", "location cell-info request failed", failure);
        }
        return result.get();
    }

    private static long longState(Map<String, Object> state, String key) {
        Object item = state.get(key);
        if (!(item instanceof Number) || item instanceof Double || item instanceof Float) {
            throw new IllegalStateException("location_state_invalid");
        }
        return ((Number) item).longValue();
    }

    /** 3GPP TS 36.101 downlink EARFCN ranges for the supported dataset bands. */
    private static int bandForEarfcn(int earfcn) {
        int[][] ranges = {
                {1, 0, 599}, {2, 600, 1199}, {3, 1200, 1949}, {4, 1950, 2399},
                {5, 2400, 2649}, {7, 2750, 3449}, {8, 3450, 3799}, {12, 5010, 5179},
                {19, 6000, 6149}, {20, 6150, 6449}, {28, 9210, 9659},
                {66, 66436, 67335}, {71, 68586, 68935},
        };
        for (int[] range : ranges) {
            if (earfcn >= range[1] && earfcn <= range[2]) return range[0];
        }
        return 0;
    }

    private void configureApn(Map<String, Object> carrier) {
        configureApn(string(carrier, "name"), string(carrier, "mcc"),
                string(carrier, "mnc"), string(carrier, "apn"));
    }

    private void configureApn(String name, String mcc, String mnc, String apn) {
        String numeric = mcc + mnc;
        ContentValues values = new ContentValues();
        values.put(Telephony.Carriers.NAME, name);
        values.put(Telephony.Carriers.NUMERIC, numeric);
        values.put(Telephony.Carriers.MCC, mcc);
        values.put(Telephony.Carriers.MNC, mnc);
        values.put(Telephony.Carriers.APN, apn);
        values.put(Telephony.Carriers.TYPE, "default,supl");
        values.put(Telephony.Carriers.PROTOCOL, "IPV4V6");
        values.put(Telephony.Carriers.ROAMING_PROTOCOL, "IPV4V6");
        values.put(Telephony.Carriers.CARRIER_ENABLED, 1);
        values.put(Telephony.Carriers.CURRENT, 1);
        values.put("edited", 1);
        values.put("user", "Xenoid");
        values.put("user_editable", 0);
        values.put("owned_by", 1);
        ContentResolver resolver = context.getContentResolver();
        int changed = resolver.update(Telephony.Carriers.CONTENT_URI, values,
                Telephony.Carriers.NUMERIC + "=? AND " + Telephony.Carriers.APN + "=?",
                new String[]{numeric, apn});
        if (changed == 0 && resolver.insert(Telephony.Carriers.CONTENT_URI, values) == null) {
            throw new IllegalStateException("location_apn_publish_failed");
        }
    }

    private boolean apnPresent(String numeric, String apn) {
        try (Cursor cursor = context.getContentResolver().query(Telephony.Carriers.CONTENT_URI,
                new String[]{Telephony.Carriers._ID},
                Telephony.Carriers.NUMERIC + "=? AND " + Telephony.Carriers.APN + "=? AND "
                        + Telephony.Carriers.CARRIER_ENABLED + "=1",
                new String[]{numeric, apn}, null)) {
            return cursor != null && cursor.moveToFirst();
        }
    }

    private static void setLocationProperties(Map<String, Object> profile, Map<String, Object> cell,
            String digest) {
        String locale = (String) array(profile, "locale").get(0);
        String command = "set -eu;setprop persist.sys.locale " + quote(locale)
                + ";setprop persist.sys.timezone " + quote(string(profile, "timezone"))
                + ";setprop persist.xenoid.radio.lte_band " + quote(Long.toString(strictLong(cell, "band", 1)))
                + ";setprop persist.xenoid.radio.lte_bandwidth_khz " + quote(Long.toString(strictLong(cell, "bandwidthKhz", 1)))
                + ";setprop persist.xenoid.radio.profile_digest " + quote(digest);
        Map<String, Object> result = RootHelper.execRootd(command);
        if (!Boolean.TRUE.equals(result.get("ok"))) throw new IllegalStateException("location_property_publish_failed");
    }

    private void convergeProvisioning() {
        // location_mode is a deprecated no-op on Q+; the supported, idempotent
        // path is the location shell command, and the Java side validates
        // through LocationManager rather than Settings.
        Map<String, Object> result = RootHelper.execRootd(
                "set -eu;settings put global device_provisioned 1;"
                        + "settings --user 0 put secure user_setup_complete 1;"
                        + "settings --user 0 put secure tv_user_setup_complete 1;"
                        + "cmd location set-location-enabled true;"
                        + "[ $(settings get global device_provisioned) = 1 ];"
                        + "[ $(settings --user 0 get secure user_setup_complete) = 1 ];"
                        + "[ $(settings --user 0 get secure tv_user_setup_complete) = 1 ]");
        if (!Boolean.TRUE.equals(result.get("ok"))) {
            throw new IllegalStateException("location_provisioning_failed");
        }
    }

    private boolean provisioned() {
        ContentResolver resolver = context.getContentResolver();
        android.location.LocationManager locationManager =
                (android.location.LocationManager) context.getSystemService(Context.LOCATION_SERVICE);
        return Settings.Global.getInt(resolver, Settings.Global.DEVICE_PROVISIONED, 0) == 1
                && Settings.Secure.getInt(resolver, "user_setup_complete", 0) == 1
                && Settings.Secure.getInt(resolver, "tv_user_setup_complete", 0) == 1
                && locationManager != null && locationManager.isLocationEnabled();
    }

    private Map<String, Object> imeSnapshot() {
        ContentResolver resolver = context.getContentResolver();
        return map("default", value(Settings.Secure.getString(resolver, Settings.Secure.DEFAULT_INPUT_METHOD)),
                "enabled", value(Settings.Secure.getString(resolver, Settings.Secure.ENABLED_INPUT_METHODS)),
                "subtype", Settings.Secure.getInt(resolver, Settings.Secure.SELECTED_INPUT_METHOD_SUBTYPE, -1));
    }

    private static boolean imeStillManaged(Map<String, Object> previous, Map<String, Object> current) {
        if (previous == null || !Boolean.TRUE.equals(previous.get("imeManaged"))) return false;
        Object expected = previous.get("imeAfter") != null ? previous.get("imeAfter") : previous.get("imeBefore");
        return sameJson(current, expected);
    }

    private static String getProperty(String name) {
        try {
            Process process = new ProcessBuilder("/system/bin/getprop", name).start();
            if (!process.waitFor(3, java.util.concurrent.TimeUnit.SECONDS) || process.exitValue() != 0) return "";
            byte[] bytes = new byte[256]; int count = process.getInputStream().read(bytes);
            return count <= 0 ? "" : new String(bytes, 0, count, StandardCharsets.UTF_8).trim();
        } catch (Exception ignored) { return ""; }
    }

    private Map<String, Object> loadState() throws Exception {
        if (!stateFile.exists()
                && !RootHelper.restoreLocationState(stateFile, android.os.Process.myUid())) return null;
        if (!stateFile.isFile() || (android.system.Os.stat(stateFile.getAbsolutePath()).st_mode & 0077) != 0) throw new IllegalStateException("location_state_invalid");
        byte[] bytes = Files.readAllBytes(stateFile.toPath());
        if (bytes.length == 0 || bytes.length > 64 * 1024) throw new IllegalStateException("location_state_invalid");
        Object parsed = new JSONTokener(new String(bytes, StandardCharsets.UTF_8)).nextValue();
        java.util.Arrays.fill(bytes, (byte) 0);
        if (!(parsed instanceof JSONObject)) throw new IllegalStateException("location_state_invalid");
        Map<String, Object> state = jsonObject((JSONObject) parsed);
        if (!STATE_SCHEMA.equals(state.get("schema"))) throw new IllegalStateException("location_state_invalid");
        return state;
    }

    private void saveState(Map<String, Object> state) throws Exception {
        byte[] bytes = canonical(state);
        File temporary = new File(stateFile.getParentFile(), ".location-identity.tmp");
        atomicWrite(temporary, bytes);
        Files.move(temporary.toPath(), stateFile.toPath(), StandardCopyOption.REPLACE_EXISTING, StandardCopyOption.ATOMIC_MOVE);
        android.system.Os.chmod(stateFile.getAbsolutePath(), 0600);
        if (!RootHelper.persistLocationState(stateFile, android.os.Process.myUid())) {
            java.util.Arrays.fill(bytes, (byte) 0);
            throw new IllegalStateException("location_state_publish_failed");
        }
        java.util.Arrays.fill(bytes, (byte) 0);
    }

    private static void atomicWrite(File file, byte[] bytes) throws Exception {
        try (FileOutputStream output = new FileOutputStream(file, false)) {
            output.write(bytes); output.flush(); output.getFD().sync();
        }
        android.system.Os.chmod(file.getAbsolutePath(), 0600);
    }

    private static Map<String, Object> publicState(Map<String, Object> state) {
        Map<String, Object> result = new LinkedHashMap<>();
        for (String key : new String[]{"state", "locationKey", "profileDigest",
                "runtimeEpoch", "countryCode", "timezone", "locale", "callingCode", "carrier",
                "operatorNumeric", "band", "earfcn", "bandwidthKhz", "imsi", "iccid", "msisdn"}) {
            if (state.containsKey(key)) result.put(key, state.get(key));
        }
        result.put("dataIface", "rmnet_data0");
        result.put("imeManaged", Boolean.TRUE.equals(state.get("imeManaged")));
        return result;
    }

    private static void assertField(Map<Integer, byte[]> fields, int id, String expected) {
        byte[] value = fields.get(id);
        if (value == null || !expected.equals(new String(value, StandardCharsets.UTF_8))) throw invalidProfile();
    }

    private static void assertInt(Map<Integer, byte[]> fields, int id, long expected) {
        byte[] value = fields.get(id);
        if (value == null || value.length != 4 || (ByteBuffer.wrap(value).order(ByteOrder.BIG_ENDIAN).getInt() & 0xffffffffL) != (expected & 0xffffffffL)) throw invalidProfile();
    }

    private static byte[] canonical(Object value) {
        StringBuilder out = new StringBuilder(); canonicalValue(value, out);
        return out.toString().getBytes(StandardCharsets.UTF_8);
    }

    private static void canonicalValue(Object value, StringBuilder out) {
        if (value == null || value == JSONObject.NULL) { out.append("null"); return; }
        if (value instanceof String) { out.append(quoteJson((String) value)); return; }
        if (value instanceof Boolean) { out.append(String.valueOf(value)); return; }
        if (value instanceof Number) {
            if (value instanceof Double || value instanceof Float) {
                double number = ((Number) value).doubleValue();
                if (!Double.isFinite(number)) throw new IllegalArgumentException("location_json_invalid");
                out.append(String.valueOf(number));
            } else {
                out.append(String.valueOf(value));
            }
            return;
        }
        if (value instanceof Map) {
            Map<?, ?> map = (Map<?, ?>) value;
            List<String> keys = new ArrayList<>(); for (Object key : map.keySet()) keys.add(String.valueOf(key));
            Collections.sort(keys); out.append('{');
            for (int i = 0; i < keys.size(); i++) { if (i > 0) out.append(','); String key = keys.get(i); out.append(quoteJson(key)).append(':'); canonicalValue(map.get(key), out); }
            out.append('}'); return;
        }
        if (value instanceof List) {
            List<?> list = (List<?>) value; out.append('[');
            for (int i = 0; i < list.size(); i++) { if (i > 0) out.append(','); canonicalValue(list.get(i), out); }
            out.append(']'); return;
        }
        throw new IllegalArgumentException("location_json_invalid");
    }

    private static Map<String, Object> jsonObject(JSONObject object) throws Exception {
        Map<String, Object> result = new LinkedHashMap<>();
        java.util.Iterator<String> keys = object.keys();
        while (keys.hasNext()) { String key = keys.next(); result.put(key, jsonValue(object.get(key))); }
        return result;
    }

    private static Object jsonValue(Object value) throws Exception {
        if (value == JSONObject.NULL) return null;
        if (value instanceof JSONObject) return jsonObject((JSONObject) value);
        if (value instanceof JSONArray) {
            JSONArray array = (JSONArray) value; List<Object> result = new ArrayList<>();
            for (int i = 0; i < array.length(); i++) result.add(jsonValue(array.get(i)));
            return result;
        }
        return value;
    }

    private static String quoteJson(String value) {
        StringBuilder out = new StringBuilder(value.length() + 2);
        out.append('"');
        for (int index = 0; index < value.length(); index++) {
            char item = value.charAt(index);
            switch (item) {
                case '"': out.append("\\\""); break;
                case '\\': out.append("\\\\"); break;
                case '\b': out.append("\\b"); break;
                case '\f': out.append("\\f"); break;
                case '\n': out.append("\\n"); break;
                case '\r': out.append("\\r"); break;
                case '\t': out.append("\\t"); break;
                default:
                    if (item < 0x20 || item > 0x7e) {
                        out.append(String.format(Locale.ROOT, "\\u%04x", (int) item));
                    } else {
                        out.append(item);
                    }
            }
        }
        return out.append('"').toString();
    }

    private static boolean sameJson(Object first, Object second) {
        try { return MessageDigest.isEqual(canonical(first), canonical(second)); }
        catch (Exception ignored) { return false; }
    }

    private static String sha256(byte[] value) throws Exception {
        byte[] digest = MessageDigest.getInstance("SHA-256").digest(value);
        StringBuilder out = new StringBuilder(64); for (byte item : digest) out.append(String.format(Locale.ROOT, "%02x", item & 0xff));
        return out.toString();
    }

    private static String firstLocale(Map<String, Object> state) {
        List<Object> locales = array(state, "locale");
        if (locales.isEmpty() || !(locales.get(0) instanceof String)) throw new IllegalStateException("location_state_invalid");
        return (String) locales.get(0);
    }

    private static String quote(String value) {
        if (!value.matches("[A-Za-z0-9_./:+-]{1,192}")) throw new IllegalArgumentException("location_value_invalid");
        return "'" + value + "'";
    }
    private static String mask(String value) { return value.length() < 4 ? "" : "********************".substring(0, Math.min(20, value.length() - 4)) + value.substring(value.length() - 4); }
    private static String value(String value) { return value == null ? "" : value; }
    private static String digits(String value, int min, int max) { if (value.length() < min || value.length() > max || !value.matches("[0-9]+")) throw invalidProfile(); return value; }
    private static String bounded(String value, int min, int max) { int length = value.getBytes(StandardCharsets.UTF_8).length; if (length < min || length > max || value.indexOf('\0') >= 0 || !value.equals(value.trim())) throw invalidProfile(); return value; }
    private static String hex64(String value) { if (!value.matches("[0-9a-f]{64}")) throw invalidProfile(); return value; }
    private static void range(long value, long min, long max) { if (value < min || value > max) throw invalidProfile(); }
    private static long strictLong(Map<String, Object> value, String key, long min) { Object item = value.get(key); if (!(item instanceof Number) || item instanceof Double || item instanceof Float) throw invalidProfile(); long result = ((Number) item).longValue(); if (result < min) throw invalidProfile(); return result; }
    private static String string(Map<String, Object> value, String key) { Object item = value.get(key); if (!(item instanceof String)) throw invalidProfile(); return (String) item; }
    @SuppressWarnings("unchecked") private static Map<String, Object> object(Map<String, Object> value, String key) { Object item = value.get(key); if (!(item instanceof Map)) throw invalidProfile(); return (Map<String, Object>) item; }
    @SuppressWarnings("unchecked") private static List<Object> array(Map<String, Object> value, String key) { Object item = value.get(key); if (!(item instanceof List)) throw invalidProfile(); return (List<Object>) item; }
    private static void requireKeys(Map<String, Object> value, String... keys) { Set<String> expected = new java.util.HashSet<>(java.util.Arrays.asList(keys)); if (!value.keySet().equals(expected)) throw new IllegalArgumentException("location_request_invalid"); }
    private static IllegalArgumentException invalidProfile() { return new IllegalArgumentException("location_profile_invalid"); }
    private static Map<String, Object> map(Object... values) { Map<String, Object> out = new LinkedHashMap<>(); for (int i = 0; i + 1 < values.length; i += 2) out.put(String.valueOf(values[i]), values[i + 1]); return out; }
}
