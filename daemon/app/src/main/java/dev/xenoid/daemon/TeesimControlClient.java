package dev.xenoid.daemon;

import android.database.Cursor;
import android.database.sqlite.SQLiteDatabase;
import android.net.LocalSocket;
import android.net.LocalSocketAddress;
import android.os.IBinder;
import android.system.Os;
import android.system.OsConstants;
import android.system.StructStat;
import org.json.JSONArray;
import org.json.JSONObject;
import org.json.JSONTokener;

import java.io.File;
import java.io.FileDescriptor;
import java.io.InputStream;
import java.io.OutputStream;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.LinkedHashSet;
import java.util.List;
import java.util.Set;

/** Root-only, one-shot bridge between the daemon's transient config and @teesim. */
public final class TeesimControlClient {
    private static final int MAX_FRAME = 8 * 1024 * 1024;
    private static final int AID_KEYSTORE = 1017;
    private static final String CONFIG_PATH =
            "/data/user/0/dev.xenoid.daemon/no_backup/keybox/control.json";
    private static final String STAGE_REQUEST_PATH =
            "/data/user/0/dev.xenoid.daemon/no_backup/keybox/.stage-request";
    private static final String CANDIDATE_PATH =
            "/data/user/0/dev.xenoid.daemon/no_backup/keybox/.candidate.xml";
    private static final String KEYSTORE_DB = "/data/misc/keystore/persistent.sqlite";
    private static final String KEYSTORE_SERVICE =
            "android.system.keystore2.IKeystoreService/default";
    private static final int DOMAIN_KEY_ID = 4;
    private static final int PURPOSE_TAG = 0x20000001;
    private static final int ATTEST_KEY_PURPOSE = 7;
    private static final String MARKER_HEX = "54454553494D6B6D00";
    private static final String GMS = "com.google.android.gms";
    private static final String VENDING = "com.android.vending";

    private TeesimControlClient() { }

    public static void main(String[] args) {
        String operation = args.length == 1 ? args[0] : "";
        String result = "native_rejected";
        byte[] config = null;
        try {
            if (Os.getuid() != 0 || args.length != 1) throw new Failure();
            if ("stage".equals(operation)) {
                result = stageKeybox(false) ? "ok" : "invalid_stage";
            } else if ("stage-cleanup".equals(operation)) {
                result = stageKeybox(true) ? "ok" : "invalid_stage";
            } else if ("apply".equals(operation) || "clear".equals(operation)) {
                config = readPrivateConfig();
                Os.remove(CONFIG_PATH);
                JSONObject object = parseConfig(config);
                if ("apply".equals(operation)) {
                    if (!applyConfig(config, object, 1)) {
                        result = "native_rejected";
                    } else {
                        result = migrateAttestationKeys(object)
                                ? "ok" : "key_migration_unavailable";
                    }
                } else {
                    result = applyConfig(config, object, 1) ? "ok" : "native_rejected";
                }
            } else {
                throw new Failure();
            }
        } catch (Throwable ignored) {
            if ("stage".equals(operation) || "stage-cleanup".equals(operation)) {
                result = "invalid_stage";
            }
        } finally {
            if (config != null) Arrays.fill(config, (byte) 0);
        }
        System.out.print("xenoid-keymint:" + result);
        System.out.flush();
        System.exit("ok".equals(result) ? 0 : 1);
    }

    private static boolean stageKeybox(boolean cleanupOnly) {
        byte[] request = null;
        StageInfo info = null;
        boolean copied = false;
        try {
            request = readStageRequest();
            info = parseStageRequest(request, cleanupOnly);
            if (cleanupOnly) return unlinkStage(info.path);
            copied = copyStage(info);
            if (!copied) return false;
            if (!unlinkStage(info.path)) {
                unlinkCandidate();
                return false;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (!cleanupOnly && !copied && info != null) unlinkStage(info.path);
            if (!cleanupOnly && !copied) unlinkCandidate();
            if (request != null) Arrays.fill(request, (byte) 0);
            if (info != null) info.destroy();
        }
    }

    private static byte[] readStageRequest() throws Exception {
        StructStat before = Os.lstat(STAGE_REQUEST_PATH);
        if (!OsConstants.S_ISREG(before.st_mode) || (before.st_mode & 0777) != 0600
                || before.st_uid < 10000 || before.st_size <= 70 || before.st_size > 512) {
            throw new Failure();
        }
        FileDescriptor descriptor = null;
        byte[] value = new byte[(int) before.st_size];
        try {
            descriptor = Os.open(STAGE_REQUEST_PATH,
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW, 0);
            StructStat opened = Os.fstat(descriptor);
            if (!sameFile(before, opened)) throw new Failure();
            int offset = 0;
            while (offset < value.length) {
                int count = Os.read(descriptor, value, offset, value.length - offset);
                if (count <= 0) throw new Failure();
                offset += count;
            }
            byte[] extra = new byte[1];
            try {
                if (Os.read(descriptor, extra, 0, 1) != 0) throw new Failure();
            } finally {
                Arrays.fill(extra, (byte) 0);
            }
            if (!sameFile(before, Os.fstat(descriptor))
                    || !sameFile(before, Os.lstat(STAGE_REQUEST_PATH))) {
                throw new Failure();
            }
            return value;
        } catch (Throwable failure) {
            Arrays.fill(value, (byte) 0);
            throw failure;
        } finally {
            try { if (descriptor != null) Os.close(descriptor); } catch (Throwable ignored) { }
        }
    }

    private static StageInfo parseStageRequest(byte[] value, boolean cleanupOnly)
            throws Exception {
        String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
        String[] lines = text.split("\n", -1);
        if (lines.length != 4 || !lines[3].isEmpty()
                || !lines[0].matches("/data/local/tmp/\\.keybox-upload-[0-9a-f]{32}")) {
            throw new Failure();
        }
        if (cleanupOnly) return new StageInfo(lines[0], 0, null, -1);
        long size;
        try {
            size = Long.parseLong(lines[1]);
        } catch (NumberFormatException ignored) {
            throw new Failure();
        }
        if (size <= 0 || size > MAX_FRAME || !lines[2].matches("[0-9a-f]{64}")) {
            throw new Failure();
        }
        byte[] digest = decodeHex(lines[2]);
        StructStat request = Os.lstat(STAGE_REQUEST_PATH);
        return new StageInfo(lines[0], size, digest, request.st_uid);
    }

    private static boolean copyStage(StageInfo info) {
        FileDescriptor source = null;
        FileDescriptor destination = null;
        byte[] buffer = new byte[64 * 1024];
        byte[] actual = null;
        boolean success = false;
        try {
            File sourceFile = new File(info.path);
            StructStat before = Os.lstat(info.path);
            if (!OsConstants.S_ISREG(before.st_mode) || before.st_uid != 2000
                    || (before.st_mode & 0777) != 0600 || before.st_size != info.size
                    || !sourceFile.getCanonicalPath().equals(sourceFile.getAbsolutePath())) {
                System.out.print("phase=source");
                return false;
            }
            File candidate = new File(CANDIDATE_PATH);
            File directory = candidate.getParentFile();
            StructStat directoryStat = Os.lstat(directory.getAbsolutePath());
            if (!OsConstants.S_ISDIR(directoryStat.st_mode)
                    || directoryStat.st_uid != info.appUid
                    || (directoryStat.st_mode & 0777) != 0700) {
                System.out.print("phase=directory");
                return false;
            }
            source = Os.open(info.path,
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW, 0);
            if (!sameFile(before, Os.fstat(source))) {
                System.out.print("phase=source-open");
                return false;
            }
            destination = Os.open(CANDIDATE_PATH,
                    OsConstants.O_WRONLY | OsConstants.O_CREAT | OsConstants.O_EXCL
                            | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW,
                    0600);
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            long total = 0;
            while (total < info.size) {
                int wanted = (int) Math.min(buffer.length, info.size - total);
                int count = Os.read(source, buffer, 0, wanted);
                if (count <= 0) {
                    System.out.print("phase=read");
                    return false;
                }
                digest.update(buffer, 0, count);
                int offset = 0;
                while (offset < count) {
                    int written = Os.write(destination, buffer, offset, count - offset);
                    if (written <= 0) {
                        System.out.print("phase=write");
                        return false;
                    }
                    offset += written;
                }
                total += count;
                Arrays.fill(buffer, 0, count, (byte) 0);
            }
            if (Os.read(source, buffer, 0, 1) != 0) {
                System.out.print("phase=eof");
                return false;
            }
            StructStat sourceAfter = Os.lstat(info.path);
            if (!sameFile(before, Os.fstat(source)) || !sameFile(before, sourceAfter)) {
                System.out.print("phase=source-change");
                return false;
            }
            actual = digest.digest();
            if (!MessageDigest.isEqual(info.sha256, actual)) {
                System.out.print("phase=digest");
                return false;
            }
            Os.fchown(destination, info.appUid, info.appUid);
            Os.fchmod(destination, 0600);
            Os.fsync(destination);
            StructStat copied = Os.fstat(destination);
            if (!OsConstants.S_ISREG(copied.st_mode) || copied.st_uid != info.appUid
                    || (copied.st_mode & 0777) != 0600 || copied.st_size != info.size) {
                System.out.print("phase=destination");
                return false;
            }
            success = true;
            return true;
        } catch (Throwable failure) {
            System.out.print("phase=copy-exception:" + failure.getClass().getName()
                    + ":" + String.valueOf(failure.getMessage()).replaceAll("[^A-Za-z0-9_.:-]", "_"));
            return false;
        } finally {
            Arrays.fill(buffer, (byte) 0);
            if (actual != null) Arrays.fill(actual, (byte) 0);
            try { if (source != null) Os.close(source); } catch (Throwable ignored) { }
            try { if (destination != null) Os.close(destination); } catch (Throwable ignored) { }
            if (!success) unlinkCandidate();
        }
    }

    private static boolean unlinkStage(String path) {
        try {
            StructStat stat = Os.lstat(path);
            if (!OsConstants.S_ISREG(stat.st_mode) || stat.st_uid != 2000
                    || (stat.st_mode & 0077) != 0
                    || !new File(path).getCanonicalPath().equals(path)) {
                return false;
            }
            Os.remove(path);
            return true;
        } catch (android.system.ErrnoException failure) {
            return failure.errno == OsConstants.ENOENT;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static void unlinkCandidate() {
        try { Os.remove(CANDIDATE_PATH); } catch (Throwable ignored) { }
    }

    private static byte[] decodeHex(String text) throws Failure {
        if (text == null || text.length() != 64) throw new Failure();
        byte[] value = new byte[32];
        for (int index = 0; index < value.length; index++) {
            int high = Character.digit(text.charAt(index * 2), 16);
            int low = Character.digit(text.charAt(index * 2 + 1), 16);
            if (high < 0 || low < 0) {
                Arrays.fill(value, (byte) 0);
                throw new Failure();
            }
            value[index] = (byte) ((high << 4) | low);
        }
        return value;
    }

    private static boolean sameFile(StructStat first, StructStat second) {
        return first.st_dev == second.st_dev && first.st_ino == second.st_ino
                && first.st_size == second.st_size && first.st_mtime == second.st_mtime
                && first.st_uid == second.st_uid && first.st_mode == second.st_mode;
    }


    private static byte[] readPrivateConfig() throws Exception {
        StructStat before = Os.lstat(CONFIG_PATH);
        if (!OsConstants.S_ISREG(before.st_mode) || (before.st_mode & 0777) != 0600
                || before.st_uid < 10000 || before.st_size <= 0 || before.st_size > MAX_FRAME) {
            throw new Failure();
        }
        FileDescriptor descriptor = null;
        byte[] value = new byte[(int) before.st_size];
        try {
            descriptor = Os.open(CONFIG_PATH,
                    OsConstants.O_RDONLY | OsConstants.O_CLOEXEC | OsConstants.O_NOFOLLOW, 0);
            if (!sameFile(before, Os.fstat(descriptor))) throw new Failure();
            int offset = 0;
            while (offset < value.length) {
                int count = Os.read(descriptor, value, offset, value.length - offset);
                if (count <= 0) throw new Failure();
                offset += count;
            }
            byte[] extra = new byte[1];
            try {
                if (Os.read(descriptor, extra, 0, 1) != 0) throw new Failure();
            } finally {
                Arrays.fill(extra, (byte) 0);
            }
            if (!sameFile(before, Os.fstat(descriptor))
                    || !sameFile(before, Os.lstat(CONFIG_PATH))) {
                throw new Failure();
            }
            return value;
        } catch (Throwable failure) {
            Arrays.fill(value, (byte) 0);
            throw failure;
        } finally {
            try { if (descriptor != null) Os.close(descriptor); } catch (Throwable ignored) { }
        }
    }

    private static JSONObject parseConfig(byte[] value) throws Exception {
        String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
        JSONTokener tokener = new JSONTokener(text);
        Object parsed = tokener.nextValue();
        if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) throw new Failure();
        JSONObject object = (JSONObject) parsed;
        if (!"config".equals(object.optString("type", ""))) throw new Failure();
        JSONArray profiles = object.optJSONArray("profiles");
        if (profiles == null) throw new Failure();
        return object;
    }

    private static boolean applyConfig(byte[] config, JSONObject object, int expectedProfiles) {
        LocalSocket socket = null;
        byte[] helloFrame = null;
        byte[] ackFrame = null;
        try {
            JSONArray profiles = object.getJSONArray("profiles");
            if (profiles.length() != expectedProfiles) return false;
            long epoch = strictLong(object, "epoch");
            socket = new LocalSocket();
            // This runtime creates the socket fd lazily inside connect();
            // calling setSoTimeout before connect fails with "socket not created".
            socket.connect(new LocalSocketAddress("teesim", LocalSocketAddress.Namespace.ABSTRACT));
            socket.setSoTimeout(15000);
            if (socket.getPeerCredentials() == null
                    || socket.getPeerCredentials().getUid() != AID_KEYSTORE) {
                return false;
            }
            InputStream input = socket.getInputStream();
            OutputStream output = socket.getOutputStream();
            helloFrame = readFrame(input);
            JSONObject hello = parseFrame(helloFrame);
            if (!"hello".equals(hello.optString("type", ""))
                    || !"lib".equals(hello.optString("role", ""))
                    || strictInt(hello, "protocol") != 1
                    || strictInt(hello, "androidApi") != 33
                    || strictInt(hello, "keystorePid") <= 0) {
                return false;
            }
            writeFrame(output, "{\"type\":\"hello\",\"role\":\"daemon\",\"protocol\":1}"
                    .getBytes(StandardCharsets.UTF_8));
            writeFrame(output, config);
            ackFrame = readFrame(input);
            JSONObject ack = parseFrame(ackFrame);
            return "ack".equals(ack.optString("type", ""))
                    && Boolean.TRUE.equals(ack.opt("ok"))
                    && strictLong(ack, "epoch") == epoch
                    && strictInt(ack, "profilesApplied") == expectedProfiles
                    && strictInt(ack, "profilesFailed") == 0;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (helloFrame != null) Arrays.fill(helloFrame, (byte) 0);
            if (ackFrame != null) Arrays.fill(ackFrame, (byte) 0);
            try { if (socket != null) socket.close(); } catch (Throwable ignored) { }
        }
    }

    private static void writeFrame(OutputStream output, byte[] value) throws Exception {
        if (value.length <= 0 || value.length > MAX_FRAME) throw new Failure();
        output.write(new byte[] {
                (byte) (value.length >>> 24), (byte) (value.length >>> 16),
                (byte) (value.length >>> 8), (byte) value.length
        });
        output.write(value);
        output.flush();
    }

    private static byte[] readFrame(InputStream input) throws Exception {
        byte[] header = new byte[4];
        readFully(input, header);
        int length = ((header[0] & 0xff) << 24) | ((header[1] & 0xff) << 16)
                | ((header[2] & 0xff) << 8) | (header[3] & 0xff);
        Arrays.fill(header, (byte) 0);
        if (length <= 0 || length > MAX_FRAME) throw new Failure();
        byte[] body = new byte[length];
        try {
            readFully(input, body);
            return body;
        } catch (Throwable failure) {
            Arrays.fill(body, (byte) 0);
            throw failure;
        }
    }

    private static void readFully(InputStream input, byte[] value) throws Exception {
        int offset = 0;
        while (offset < value.length) {
            int count = input.read(value, offset, value.length - offset);
            if (count <= 0) throw new Failure();
            offset += count;
        }
    }

    private static JSONObject parseFrame(byte[] value) throws Exception {
        String text = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT)
                .decode(ByteBuffer.wrap(value)).toString();
        JSONTokener tokener = new JSONTokener(text);
        Object parsed = tokener.nextValue();
        if (!(parsed instanceof JSONObject) || tokener.nextClean() != 0) throw new Failure();
        return (JSONObject) parsed;
    }

    private static int strictInt(JSONObject object, String key) throws Exception {
        long value = strictLong(object, key);
        if (value < Integer.MIN_VALUE || value > Integer.MAX_VALUE) throw new Failure();
        return (int) value;
    }

    private static long strictLong(JSONObject object, String key) throws Exception {
        Object value = object.get(key);
        if (!(value instanceof Byte) && !(value instanceof Short)
                && !(value instanceof Integer) && !(value instanceof Long)) {
            throw new Failure();
        }
        return ((Number) value).longValue();
    }

    private static boolean migrateAttestationKeys(JSONObject config) {
        SQLiteDatabase database = null;
        try {
            Set<Integer> targets = targetUids(config);
            if (targets.isEmpty()) return true;
            File source = new File(KEYSTORE_DB);
            StructStat stat = Os.lstat(KEYSTORE_DB);
            if (!OsConstants.S_ISREG(stat.st_mode)
                    || !source.getCanonicalPath().equals(source.getAbsolutePath())) {
                return false;
            }
            database = SQLiteDatabase.openDatabase(
                    KEYSTORE_DB, null, SQLiteDatabase.OPEN_READONLY);
            if (!hasColumns(database, "keyentry", "id", "domain", "namespace")
                    || !hasColumns(database, "keyparameter", "keyentryid", "tag", "data")
                    || !hasColumns(database, "blobentry", "keyentryid", "blob")) {
                return false;
            }
            List<KeyRef> keys = targetAttestKeys(database, targets);
            database.close();
            database = null;
            for (KeyRef key : keys) {
                Eligibility eligibility = eligibility(key, targets);
                if (eligibility == Eligibility.ABSENT) continue;
                if (eligibility != Eligibility.ELIGIBLE || !deleteAsOwner(key)) return false;
                if (!waitUntilAbsent(key.id)) return false;
            }
            return true;
        } catch (Throwable ignored) {
            return false;
        } finally {
            try { if (database != null) database.close(); } catch (Throwable ignored) { }
        }
    }

    private static Set<Integer> targetUids(JSONObject config) throws Exception {
        JSONArray profiles = config.getJSONArray("profiles");
        if (profiles.length() != 1) throw new Failure();
        JSONObject profile = profiles.getJSONObject(0);
        JSONArray uids = profile.getJSONArray("uids");
        JSONArray packages = profile.getJSONArray("uidPackages");
        if (uids.length() != packages.length()) throw new Failure();
        Set<Integer> result = new LinkedHashSet<>();
        for (int index = 0; index < uids.length(); index++) {
            Object raw = uids.get(index);
            if (!(raw instanceof Integer) && !(raw instanceof Long)) throw new Failure();
            long uid = ((Number) raw).longValue();
            String packageName = packages.getString(index);
            if ((GMS.equals(packageName) || VENDING.equals(packageName))
                    && uid >= 10000 && uid <= Integer.MAX_VALUE) {
                result.add((int) uid);
            }
        }
        return result;
    }

    private static boolean hasColumns(SQLiteDatabase database, String table, String... required) {
        Set<String> columns = new LinkedHashSet<>();
        try (Cursor cursor = database.rawQuery("PRAGMA table_info(" + table + ")", null)) {
            int name = cursor.getColumnIndex("name");
            if (name < 0) return false;
            while (cursor.moveToNext()) columns.add(cursor.getString(name));
        }
        return columns.containsAll(Arrays.asList(required));
    }

    private static List<KeyRef> targetAttestKeys(
            SQLiteDatabase database, Set<Integer> targets) {
        String placeholders = placeholders(targets.size());
        String[] arguments = new String[targets.size()];
        int index = 0;
        for (Integer uid : targets) arguments[index++] = uid.toString();
        List<KeyRef> result = new ArrayList<>();
        String sql = "SELECT k.id,k.namespace FROM keyentry k "
                + "WHERE k.domain=0 AND k.namespace IN (" + placeholders + ") "
                + "AND EXISTS (SELECT 1 FROM keyparameter p WHERE p.keyentryid=k.id "
                + "AND p.tag=" + PURPOSE_TAG + " AND p.data=" + ATTEST_KEY_PURPOSE + ") "
                + "AND NOT EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid=k.id "
                + "AND substr(b.blob,1,9)=X'" + MARKER_HEX + "')";
        try (Cursor cursor = database.rawQuery(sql, arguments)) {
            while (cursor.moveToNext()) {
                long id = cursor.getLong(0);
                int uid = cursor.getInt(1);
                if (id <= 0 || !targets.contains(uid)) throw new IllegalStateException();
                result.add(new KeyRef(id, uid));
            }
        }
        return result;
    }

    private static Eligibility eligibility(KeyRef key, Set<Integer> targets) {
        if (!targets.contains(key.uid)) return Eligibility.UNSAFE;
        SQLiteDatabase database = null;
        try {
            database = SQLiteDatabase.openDatabase(
                    KEYSTORE_DB, null, SQLiteDatabase.OPEN_READONLY);
            try (Cursor present = database.rawQuery(
                    "SELECT domain,namespace FROM keyentry WHERE id=?",
                    new String[] { Long.toString(key.id) })) {
                if (!present.moveToNext()) return Eligibility.ABSENT;
                if (present.getInt(0) != 0 || present.getInt(1) != key.uid) {
                    return Eligibility.UNSAFE;
                }
            }
            try (Cursor eligible = database.rawQuery(
                    "SELECT 1 FROM keyentry k WHERE k.id=? AND k.domain=0 AND k.namespace=? "
                            + "AND EXISTS (SELECT 1 FROM keyparameter p WHERE p.keyentryid=k.id "
                            + "AND p.tag=" + PURPOSE_TAG + " AND p.data=" + ATTEST_KEY_PURPOSE + ") "
                            + "AND NOT EXISTS (SELECT 1 FROM blobentry b WHERE b.keyentryid=k.id "
                            + "AND substr(b.blob,1,9)=X'" + MARKER_HEX + "')",
                    new String[] { Long.toString(key.id), Integer.toString(key.uid) })) {
                return eligible.moveToNext() ? Eligibility.ELIGIBLE : Eligibility.UNSAFE;
            }
        } catch (Throwable ignored) {
            return Eligibility.UNSAFE;
        } finally {
            try { if (database != null) database.close(); } catch (Throwable ignored) { }
        }
    }

    private static boolean deleteAsOwner(KeyRef key) {
        boolean restored = false;
        try {
            Os.seteuid(key.uid);
            boolean deleted = deleteKeyById(key.id);
            Os.seteuid(0);
            restored = true;
            return deleted;
        } catch (Throwable ignored) {
            return false;
        } finally {
            if (!restored) {
                try { Os.seteuid(0); } catch (Throwable ignored) { }
            }
        }
    }

    private static boolean deleteKeyById(long keyId) {
        try {
            Class<?> serviceManager = Class.forName("android.os.ServiceManager");
            IBinder binder = (IBinder) serviceManager
                    .getMethod("getService", String.class).invoke(null, KEYSTORE_SERVICE);
            if (binder == null) return false;
            Class<?> stub = Class.forName("android.system.keystore2.IKeystoreService$Stub");
            Object service = stub.getMethod("asInterface", IBinder.class).invoke(null, binder);
            Class<?> iface = Class.forName("android.system.keystore2.IKeystoreService");
            Class<?> descriptorClass = Class.forName("android.system.keystore2.KeyDescriptor");
            Object descriptor = descriptorClass.getConstructor().newInstance();
            descriptorClass.getField("domain").setInt(descriptor, DOMAIN_KEY_ID);
            descriptorClass.getField("nspace").setLong(descriptor, keyId);
            iface.getMethod("deleteKey", descriptorClass).invoke(service, descriptor);
            return true;
        } catch (Throwable ignored) {
            return false;
        }
    }

    private static boolean waitUntilAbsent(long keyId) {
        for (int attempt = 0; attempt < 20; attempt++) {
            SQLiteDatabase database = null;
            try {
                database = SQLiteDatabase.openDatabase(
                        KEYSTORE_DB, null, SQLiteDatabase.OPEN_READONLY);
                try (Cursor cursor = database.rawQuery(
                        "SELECT 1 FROM keyentry WHERE id=?",
                        new String[] { Long.toString(keyId) })) {
                    if (!cursor.moveToNext()) return true;
                }
            } catch (Throwable ignored) {
                return false;
            } finally {
                try { if (database != null) database.close(); } catch (Throwable ignored) { }
            }
            try {
                Thread.sleep(50);
            } catch (InterruptedException ignored) {
                Thread.currentThread().interrupt();
                return false;
            }
        }
        return false;
    }

    private static String placeholders(int count) {
        StringBuilder value = new StringBuilder(count * 2);
        for (int index = 0; index < count; index++) {
            if (index > 0) value.append(',');
            value.append('?');
        }
        return value.toString();
    }

    private static final class StageInfo {
        final String path;
        final long size;
        final byte[] sha256;
        final int appUid;
        StageInfo(String path, long size, byte[] sha256, int appUid) {
            this.path = path;
            this.size = size;
            this.sha256 = sha256;
            this.appUid = appUid;
        }
        void destroy() {
            if (sha256 != null) Arrays.fill(sha256, (byte) 0);
        }
    }

    private enum Eligibility { ABSENT, ELIGIBLE, UNSAFE }

    private static final class KeyRef {
        final long id;
        final int uid;
        KeyRef(long id, int uid) { this.id = id; this.uid = uid; }
    }

    private static final class Failure extends Exception { }
}
