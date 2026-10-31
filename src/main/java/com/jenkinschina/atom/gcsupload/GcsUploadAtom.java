package com.jenkinschina.atom.gcsupload;

import com.jenkinschina.atom.sdk.AtomContext;
import com.jenkinschina.atom.sdk.AtomResult;
import com.jenkinschina.atom.sdk.AtomTask;
import com.jenkinschina.atom.sdk.ErrorType;
import com.jenkinschina.atom.sdk.Glob;
import com.jenkinschina.atom.sdk.Json;
import java.net.URI;
import java.net.URLEncoder;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.Signature;
import java.security.spec.PKCS8EncodedKeySpec;
import java.time.Duration;
import java.time.Instant;
import java.util.ArrayList;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Upload objects to a Google Cloud Storage bucket with a service account.
 *
 * <p>Two round trips: exchange a self-signed JWT (RS256) for an access token, then upload with it. The token exchange
 * is where this fails quietly in practice — a wrong audience or scope comes back as a 400 with a paragraph of text —
 * so the smoke's fake token endpoint verifies the JWT signature and checks the claims it was given.
 */
public class GcsUploadAtom implements AtomTask {

    static final String SCOPE = "https://www.googleapis.com/auth/devstorage.read_write";
    static final String GRANT = "urn:ietf:params:oauth:grant-type:jwt-bearer";

    @Override
    public AtomResult run(AtomContext context) throws Exception {
        Path workspace = context.getWorkspace();
        String bucket = context.getParam("bucket", "").trim();
        String clientEmail = context.getParam("clientEmail", "").trim();
        String privateKey = context.getSecret("privateKey");
        if (privateKey == null) {
            privateKey = context.getParam("privateKey", "");
        }
        String files = context.getParam("files", "**/*.jar");
        String prefix = context.getParam("objectPrefix", "").trim();
        String tokenUrl = context.getParam("tokenUrl", "https://oauth2.googleapis.com/token").trim();
        String uploadUrl = context.getParam("uploadUrl", "https://storage.googleapis.com").trim();
        String contentTypeOverride = context.getParam("contentType", "").trim();
        boolean failOnError = context.getBooleanParam("failOnError", true);
        int timeoutSeconds = Math.max(10, Math.min(context.getIntParam("timeoutSeconds", 120), 1800));

        if (bucket.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40001, "bucket is required");
        }
        if (clientEmail.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40002, "clientEmail is required (the service account address)");
        }
        if (privateKey == null || privateKey.isBlank()) {
            return AtomResult.error(ErrorType.USER, 40003, "privateKey is required (the service account key, PEM)");
        }

        List<Path> found = Glob.find(workspace, files);
        if (found.isEmpty()) {
            return AtomResult.error(ErrorType.USER, 40004, "nothing matched " + files);
        }

        HttpClient client = HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(timeoutSeconds)).build();
        String token;
        try {
            token = accessToken(client, tokenUrl, clientEmail, privateKey, timeoutSeconds, context);
        } catch (TokenException e) {
            return AtomResult.error(e.type, e.code, e.getMessage());
        }

        List<String> urls = new ArrayList<>();
        List<String> failures = new ArrayList<>();
        long bytes = 0;

        for (Path file : found) {
            Path relative = workspace.relativize(file);
            String name = prefix.isEmpty()
                    ? relative.toString().replace('\\', '/')
                    : prefix + "/" + relative.getFileName();
            String url = uploadUrl.replaceAll("/+$", "") + "/upload/storage/v1/b/" + encode(bucket)
                    + "/o?uploadType=media&name=" + encode(name);
            byte[] content = Files.readAllBytes(file);
            String contentType = contentTypeOverride.isEmpty() ? contentType(file) : contentTypeOverride;

            context.log("[gcs] upload " + bucket + "/" + name + " (" + content.length + " bytes)");
            HttpRequest request = HttpRequest.newBuilder(URI.create(url))
                    .timeout(Duration.ofSeconds(timeoutSeconds))
                    .header("Authorization", "Bearer " + token)
                    .header("Content-Type", contentType)
                    .header("User-Agent", "jenkins-atom-gcs-upload")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(content))
                    .build();
            HttpResponse<String> response;
            try {
                response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
            } catch (java.net.http.HttpConnectTimeoutException e) {
                return AtomResult.error(ErrorType.ENVIRONMENT, 40005,
                        "could not reach " + uploadUrl + " within " + timeoutSeconds + "s");
            } catch (java.io.IOException e) {
                return AtomResult.error(ErrorType.THIRD_PART, 40006,
                        "uploading " + name + " failed: " + e.getMessage());
            }
            int status = response.statusCode();
            if (status < 200 || status >= 300) {
                String reason = "HTTP " + status + " uploading " + name + ": " + excerpt(response.body());
                if (failOnError) {
                    ErrorType type = status == 401 || status == 403 ? ErrorType.USER
                            : status == 404 ? ErrorType.USER : ErrorType.THIRD_PART;
                    return AtomResult.error(type, 40007, reason);
                }
                failures.add(reason);
                context.log("[gcs] warning: " + reason);
                continue;
            }
            String selfLink = "";
            try {
                if (Json.parse(response.body()) instanceof Map<?, ?> object && object.get("selfLink") != null) {
                    selfLink = String.valueOf(object.get("selfLink"));
                }
            } catch (RuntimeException ignored) {
                // a body without JSON is fine; the status said it worked
            }
            bytes += content.length;
            urls.add(selfLink.isEmpty() ? "gs://" + bucket + "/" + name : selfLink);
        }

        Map<String, String> outputs = new LinkedHashMap<>();
        outputs.put("uploaded", String.valueOf(urls.size()));
        outputs.put("failed", String.valueOf(failures.size()));
        outputs.put("bytes", String.valueOf(bytes));
        outputs.put("bucket", bucket);
        outputs.put("urls", String.join("\n", urls.size() > 20 ? urls.subList(0, 20) : urls));
        if (!urls.isEmpty()) {
            outputs.put("first", urls.get(0));
        }
        context.log("[gcs] " + urls.size() + " object(s), " + bytes + " bytes");
        AtomResult result = AtomResult.success();
        outputs.forEach(result::data);
        return result;
    }

    /** Exchange the self-signed assertion for an access token. */
    private static String accessToken(HttpClient client, String tokenUrl, String clientEmail, String privateKey,
                                      int timeoutSeconds, AtomContext context)
            throws TokenException, InterruptedException {
        String assertion;
        try {
            long now = Instant.now().getEpochSecond();
            Map<String, Object> header = new LinkedHashMap<>();
            header.put("alg", "RS256");
            header.put("typ", "JWT");
            Map<String, Object> claims = new LinkedHashMap<>();
            claims.put("iss", clientEmail);
            claims.put("scope", SCOPE);
            claims.put("aud", tokenUrl);
            claims.put("iat", now);
            claims.put("exp", now + 3600);
            assertion = sign(header, claims, privateKey);
        } catch (Exception e) {
            throw new TokenException(ErrorType.USER, 40008,
                    "the service account private key could not sign the assertion: " + e.getMessage());
        }

        String body = "grant_type=" + encode(GRANT) + "&assertion=" + encode(assertion);
        HttpRequest request = HttpRequest.newBuilder(URI.create(tokenUrl))
                .timeout(Duration.ofSeconds(timeoutSeconds))
                .header("Content-Type", "application/x-www-form-urlencoded")
                .header("User-Agent", "jenkins-atom-gcs-upload")
                .POST(HttpRequest.BodyPublishers.ofString(body, StandardCharsets.UTF_8))
                .build();
        HttpResponse<String> response;
        try {
            response = client.send(request, HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
        } catch (java.net.http.HttpConnectTimeoutException e) {
            throw new TokenException(ErrorType.ENVIRONMENT, 40009,
                    "could not reach the token endpoint within " + timeoutSeconds + "s: " + tokenUrl);
        } catch (java.io.IOException e) {
            throw new TokenException(ErrorType.THIRD_PART, 40010,
                    "the token exchange failed: " + e.getMessage());
        }
        int status = response.statusCode();
        String text = response.body() == null ? "" : response.body();
        if (status < 200 || status >= 300) {
            // Google's error body names the problem (invalid_grant, invalid_scope, ...): pass it through
            throw new TokenException(status == 400 || status == 401 ? ErrorType.USER : ErrorType.THIRD_PART,
                    status == 400 || status == 401 ? 40011 : 40012,
                    "the token exchange was refused (HTTP " + status + "): " + excerpt(text));
        }
        try {
            Object parsed = Json.parse(text);
            if (parsed instanceof Map<?, ?> map && map.get("access_token") != null) {
                String token = String.valueOf(map.get("access_token"));
                context.log("[gcs] token acquired (" + (token.length() > 12 ? token.substring(0, 6) + "…" : "…")
                        + ", " + (map.get("expires_in") == null ? "?" : String.valueOf(map.get("expires_in"))) + "s)");
                return token;
            }
        } catch (RuntimeException ignored) {
            // fall through to the error below
        }
        throw new TokenException(ErrorType.THIRD_PART, 40013,
                "the token endpoint answered without access_token: " + excerpt(text));
    }

    /** base64url(header).base64url(claims).base64url(RS256 signature) */
    static String sign(Map<String, Object> header, Map<String, Object> claims, String pem) throws Exception {
        String signingInput = base64Url(Json.write(header).getBytes(StandardCharsets.UTF_8)) + "."
                + base64Url(Json.write(claims).getBytes(StandardCharsets.UTF_8));
        Signature signature = Signature.getInstance("SHA256withRSA");
        signature.initSign(privateKey(pem));
        signature.update(signingInput.getBytes(StandardCharsets.US_ASCII));
        return signingInput + "." + base64Url(signature.sign());
    }

    static PrivateKey privateKey(String pem) throws Exception {
        String body = pem.replace("-----BEGIN PRIVATE KEY-----", "")
                .replace("-----END PRIVATE KEY-----", "")
                .replaceAll("\\s", "");
        byte[] der = Base64.getDecoder().decode(body);
        return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
    }

    static String base64Url(byte[] content) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(content);
    }

    static String contentType(Path file) {
        String name = file.getFileName().toString().toLowerCase(java.util.Locale.ROOT);
        if (name.endsWith(".jar") || name.endsWith(".zip") || name.endsWith(".war")) {
            return "application/zip";
        }
        if (name.endsWith(".json")) {
            return "application/json";
        }
        if (name.endsWith(".html")) {
            return "text/html";
        }
        if (name.endsWith(".txt") || name.endsWith(".log")) {
            return "text/plain";
        }
        return "application/octet-stream";
    }

    private static String encode(String value) {
        return URLEncoder.encode(value, StandardCharsets.UTF_8).replace("+", "%20");
    }

    private static String excerpt(String body) {
        String oneLine = body == null ? "" : body.replaceAll("\\s+", " ").trim();
        return oneLine.length() > 240 ? oneLine.substring(0, 240) + "…" : oneLine;
    }

    /** A failed token exchange carries its own type/code, because it is not the upload's failure. */
    static final class TokenException extends Exception {
        final ErrorType type;
        final int code;

        TokenException(ErrorType type, int code, String message) {
            super(message);
            this.type = type;
            this.code = code;
        }
    }
}
