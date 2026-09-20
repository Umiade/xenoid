package dev.xenoid.daemon;

import static org.junit.Assert.assertEquals;

import java.util.LinkedHashMap;
import java.util.Map;

import org.json.JSONObject;
import org.junit.Test;

/** Escaped-backslash contracts for the package-private JSON string reader. */
public class SimpleJsonTest {
    @Test
    public void escapedBackslashBeforeEscapeLetterKeepsBackslash() {
        // Wire form of the shell command printf '%s\n' ce: the backslash is
        // JSON-escaped, so the captured group holds two backslashes then 'n'.
        // A naive "\n"-first replace would corrupt it into backslash+newline.
        String body = "{\"command\":\"printf '%s\\\\n' ce\"}";
        assertEquals("printf '%s\\n' ce", SimpleJson.stringValue(body, "command", ""));
    }

    @Test
    public void realNewlineEscapeDecodes() {
        String body = "{\"command\":\"line1\\nline2\"}";
        assertEquals("line1\nline2", SimpleJson.stringValue(body, "command", ""));
    }

    @Test
    public void escapedQuoteStaysInsideValue() {
        // Values with double quotes must survive intact: the token regex
        // honors JSON escaping instead of terminating at the first escaped
        // quote (the /root/exec corruption that broke Google wipe markers).
        String body = "{\"command\":\"say \\\"hi\\\" \\/ ok\"}";
        assertEquals("say \"hi\" / ok", SimpleJson.stringValue(body, "command", ""));
    }

    @Test
    public void escapedSolidusAndTabDecode() {
        String body = "{\"command\":\"a \\/ b\\tc\"}";
        assertEquals("a / b\tc", SimpleJson.stringValue(body, "command", ""));
    }

    @Test
    public void googleIdentitySuccessResponseRoundTripsStrictly() {
        String digest = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("ok", true);
        response.put("schema", "dev.xenoid.google-identity/v1");
        response.put("advertisingIdSha256", digest);
        response.put("gsfAndroidIdPresent", true);
        response.put("gsfAndroidIdSha256", digest);
        response.put("offlineSeeded", true);

        String body = new JSONObject(response).toString();
        assertEquals(true, SimpleJson.boolValue(body, "ok", false));
        assertEquals("dev.xenoid.google-identity/v1",
                SimpleJson.stringValue(body, "schema", ""));
        assertEquals(digest, SimpleJson.stringValue(body, "advertisingIdSha256", ""));
        assertEquals(true, SimpleJson.boolValue(body, "gsfAndroidIdPresent", false));
        assertEquals(digest, SimpleJson.stringValue(body, "gsfAndroidIdSha256", ""));
        assertEquals(true, SimpleJson.boolValue(body, "offlineSeeded", false));
    }

    @Test
    public void googleIdentityFailureResponseRoundTripsStableCode() {
        Map<String, Object> response = new LinkedHashMap<>();
        response.put("ok", false);
        response.put("schema", "dev.xenoid.google-identity/v1");
        response.put("error", "google_identity_provider_unsupported");

        String body = new JSONObject(response).toString();
        assertEquals(false, SimpleJson.boolValue(body, "ok", true));
        assertEquals("dev.xenoid.google-identity/v1",
                SimpleJson.stringValue(body, "schema", ""));
        assertEquals("google_identity_provider_unsupported",
                SimpleJson.stringValue(body, "error", ""));
    }
}
