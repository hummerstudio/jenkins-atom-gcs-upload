package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;
import java.io.IOException;
import java.net.InetSocketAddress;
import java.net.ServerSocket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Collections;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The failure half of the gcs-upload atom: what it does with a token endpoint that refuses, answers something that is
 * not a token, or does not answer at all, and with uploads that are rejected or acknowledged without an object.
 *
 * <p>The endpoint is a {@link HttpServer} this test controls, so every status and body is chosen here instead of
 * inferred from a script; {@code GcsUploadIT} keeps the real-bytes happy path against the fake in {@code tools/}.
 */
class GcsUploadContractIT {

    private static KeyPair keys;
    private static String privatePem;

    private Atom atom;
    private Stub stub;
    private final List<HttpServer> servers = new ArrayList<>();

    @BeforeEach
    void setUp() throws Exception {
        atom = Atom.of();
        if (keys == null) {
            KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            keys = generator.generateKeyPair();
            privatePem = "-----BEGIN PRIVATE KEY-----\n"
                    + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                            .encodeToString(keys.getPrivate().getEncoded())
                    + "\n-----END PRIVATE KEY-----\n";
        }
        stub = start();
    }

    @AfterEach
    void tearDown() {
        for (HttpServer server : servers) {
            server.stop(0);
        }
        servers.clear();
    }

    /** One recorded request: the method, the path, the object name, the content type and how many bytes arrived. */
    private record Seen(String method, String path, String name, String contentType, String authorization, int size) {}

    /** A GCS-shaped endpoint whose answers this test sets: token status/body, upload status/body. */
    private static final class Stub {
        private final HttpServer server;
        private final int port;
        private final List<Seen> seen = Collections.synchronizedList(new ArrayList<>());
        private volatile int tokenStatus = 200;
        private volatile String tokenBody =
                "{\"access_token\":\"ya29.stub-access-token\",\"expires_in\":3599,\"token_type\":\"Bearer\"}";
        private volatile int uploadStatus = 200;
        private volatile String uploadBody = "{\"selfLink\":\"https://storage.example/objects/app\"}";

        private Stub(HttpServer server, int port) {
            this.server = server;
            this.port = port;
        }

        private String url() {
            return "http://127.0.0.1:" + port;
        }

        private List<Seen> uploads() {
            synchronized (seen) {
                return seen.stream().filter(request -> !request.path().startsWith("/token")).toList();
            }
        }
    }

    private Stub start() throws IOException {
        HttpServer server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        Stub stub = new Stub(server, server.getAddress().getPort());
        server.createContext("/", exchange -> answer(exchange, stub));
        server.start();
        servers.add(server);
        return stub;
    }

    private static void answer(HttpExchange exchange, Stub stub) throws IOException {
        byte[] body = exchange.getRequestBody().readAllBytes();
        String path = exchange.getRequestURI().getPath();
        String query = exchange.getRequestURI().getQuery() == null ? "" : exchange.getRequestURI().getQuery();
        String name = "";
        for (String pair : query.split("&")) {
            if (pair.startsWith("name=")) {
                name = java.net.URLDecoder.decode(pair.substring(5), StandardCharsets.UTF_8);
            }
        }
        stub.seen.add(new Seen(exchange.getRequestMethod(), path, name,
                String.valueOf(exchange.getRequestHeaders().getFirst("Content-Type")),
                String.valueOf(exchange.getRequestHeaders().getFirst("Authorization")), body.length));
        int status = path.startsWith("/token") ? stub.tokenStatus : stub.uploadStatus;
        String answer = path.startsWith("/token") ? stub.tokenBody : stub.uploadBody;
        byte[] bytes = answer.getBytes(StandardCharsets.UTF_8);
        exchange.getResponseHeaders().add("Content-Type", "application/json");
        exchange.sendResponseHeaders(status, bytes.length == 0 ? -1 : bytes.length);
        if (bytes.length > 0) {
            exchange.getResponseBody().write(bytes);
        }
        exchange.close();
    }

    /** A port nothing listens on: connecting is an IOException, not an HTTP answer. */
    private static int deadPort() throws IOException {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private Atom upload(String prefix) {
        return atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("build/libs/app-1.0.0.jar", "jar-bytes")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url())
                .input("objectPrefix", prefix);
    }

    @Test
    @DisplayName("a PEM handed over as an input, with no credential bound, still signs the assertion")
    void acceptsTheKeyAsAnInput() throws Exception {
        AtomResult run = Atom.of()
                .file("build/libs/app-1.0.0.jar", "jar-bytes")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("privateKey", privatePem)
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url())
                .run();

        run.assertOk();
        assertEquals("1", run.field("uploaded"), run.file("output.json"));
        assertEquals(1, stub.uploads().size());
        assertEquals("Bearer ya29.stub-access-token", stub.uploads().get(0).authorization(),
                "the input key did not produce a usable token");
    }

    @Test
    @DisplayName("clientEmail and privateKey are required, and neither refusal reaches the endpoint")
    void refusesIncompleteCredentials() throws Exception {
        AtomResult noEmail = atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("build/libs/app-1.0.0.jar", "x")
                .input("bucket", "acme-artifacts")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url())
                .run();
        noEmail.assertRefused();
        assertTrue(noEmail.file("output.json").contains("clientEmail is required"),
                noEmail.file("output.json"));

        AtomResult blankKey = atom.file(".secrets.json", Json.write(Map.of("privateKey", "")))
                .file("build/libs/app-1.0.0.jar", "x")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url())
                .run();
        blankKey.assertRefused();
        assertTrue(blankKey.file("output.json").contains("privateKey is required"),
                blankKey.file("output.json"));
        assertTrue(stub.seen.isEmpty(), "a credential refusal reached the endpoint: " + stub.seen);
    }

    @Test
    @DisplayName("a pattern that matches nothing is refused before the token exchange")
    void refusesWhenNothingMatches() throws Exception {
        AtomResult run = upload("").input("files", "build/*.whl").run();

        run.assertRefused();
        assertTrue(run.file("output.json").contains("nothing matched build/*.whl"),
                run.file("output.json"));
        assertTrue(stub.seen.isEmpty(), "an empty match still called the endpoint: " + stub.seen);
    }

    @Test
    @DisplayName("the Content-Type follows the file name, and a contentType input overrides it")
    void picksTheContentTypePerFile() throws Exception {
        AtomResult run = atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("dist/report.txt", "text")
                .file("dist/data.json", "{}")
                .file("dist/index.html", "<html/>")
                .file("dist/lib.zip", "PK")
                .file("dist/blob.bin", "??")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("files", "dist/*")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url())
                .run();

        run.assertOk();
        assertEquals("5", run.field("uploaded"), run.file("output.json"));
        Map<String, String> types = new java.util.LinkedHashMap<>();
        for (Seen seen : stub.uploads()) {
            types.put(seen.name(), seen.contentType());
        }
        assertEquals("text/plain", types.get("dist/report.txt"), types.toString());
        assertEquals("application/json", types.get("dist/data.json"), types.toString());
        assertEquals("text/html", types.get("dist/index.html"), types.toString());
        assertEquals("application/zip", types.get("dist/lib.zip"), types.toString());
        assertEquals("application/octet-stream", types.get("dist/blob.bin"), types.toString());

        AtomResult overridden = atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("dist/report.txt", "text")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("files", "dist/*")
                .input("contentType", "text/x-custom")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url())
                .run();
        overridden.assertOk();
        assertEquals("text/x-custom", stub.uploads().get(stub.uploads().size() - 1).contentType(),
                "the contentType input did not win over the file name");
    }

    @Test
    @DisplayName("a token endpoint that cannot be reached is an environment error naming the URL")
    void reportsAnUnreachableTokenEndpoint() throws Exception {
        int dead = deadPort();
        AtomResult run = atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("build/libs/app-1.0.0.jar", "x")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("tokenUrl", "http://127.0.0.1:" + dead + "/token")
                .input("uploadUrl", stub.url())
                .run();

        run.assertRefused();
        String output = run.file("output.json");
        assertTrue(output.contains("the token exchange failed"), output);
        assertTrue(output.contains("\"errorCode\":40010"),
                "a refused connection is the token exchange's own code: " + output);
        assertTrue(output.contains("\"errorType\":2"),
                "the atom reports a refused connection as THIRD_PART (2): " + output);
        assertTrue(run.console().contains("token exchange failed"), run.console());
    }

    @Test
    @DisplayName("an upload endpoint that cannot be reached is a third-party error, not a silent success")
    void reportsAnUnreachableUploadEndpoint() throws Exception {
        int dead = deadPort();
        AtomResult run = atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("build/libs/app-1.0.0.jar", "x")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", "http://127.0.0.1:" + dead)
                .run();

        run.assertRefused();
        assertTrue(run.file("output.json").contains("uploading build/libs/app-1.0.0.jar failed"),
                run.file("output.json"));
    }

    @Test
    @DisplayName("a refused token exchange says which status, and a 500 is not blamed on the credentials")
    void mapsTokenRefusals() throws Exception {
        stub.tokenStatus = 500;
        stub.tokenBody = "{\"error\":\"backend\"}";
        AtomResult serverError = upload("").run();
        serverError.assertRefused();
        assertTrue(serverError.file("output.json").contains("HTTP 500"), serverError.file("output.json"));
        assertTrue(serverError.file("output.json").contains("\"errorType\":2"),
                "a 500 is THIRD_PART (2): " + serverError.file("output.json"));

        stub.tokenStatus = 401;
        stub.tokenBody = "{\"error\":\"invalid_grant\"}";
        AtomResult unauthorized = upload("").run();
        unauthorized.assertRefused();
        assertTrue(unauthorized.file("output.json").contains("HTTP 401"), unauthorized.file("output.json"));
        assertTrue(unauthorized.file("output.json").contains("\"errorType\":1"),
                "a 401 is USER (1): " + unauthorized.file("output.json"));
        assertTrue(unauthorized.file("output.json").contains("invalid_grant"),
                unauthorized.file("output.json"));
    }

    @Test
    @DisplayName("a token answer without access_token is refused, with the body quoted")
    void refusesAResponseWithoutAnAccessToken() throws Exception {
        stub.tokenStatus = 200;
        stub.tokenBody = "{\"expires_in\":3599}";
        AtomResult missing = upload("").run();
        missing.assertRefused();
        assertTrue(missing.file("output.json").contains("without access_token"), missing.file("output.json"));

        stub.tokenBody = "<html>not json at all</html>";
        AtomResult notJson = upload("").run();
        notJson.assertRefused();
        assertTrue(notJson.file("output.json").contains("without access_token"),
                notJson.file("output.json"));
    }

    @Test
    @DisplayName("the token log line names the expiry and never the token itself")
    void logsTheTokenWithoutLeakingIt() throws Exception {
        stub.tokenBody = "{\"access_token\":\"short\",\"expires_in\":3599}";
        AtomResult shortToken = upload("").run();
        shortToken.assertOk();
        assertTrue(shortToken.console().contains("token acquired"), shortToken.console());
        assertFalse(shortToken.console().contains("short"), "the token reached the log:\n" + shortToken.console());

        stub.tokenBody = "{\"access_token\":\"ya29.a-very-long-token-value\"}";
        AtomResult longToken = upload("").run();
        longToken.assertOk();
        assertTrue(longToken.console().contains("ya29.a…"), longToken.console());
        assertTrue(longToken.console().contains("?s"), "an answer without expires_in is not reported as unknown:\n"
                + longToken.console());
    }

    @Test
    @DisplayName("a rejected upload is refused with the status and the reason, and 403 is a credential problem")
    void mapsUploadRefusals() throws Exception {
        stub.uploadStatus = 403;
        stub.uploadBody = "{\"error\":{\"code\":403,\"message\":\"no storage.objects.create\"}}";
        AtomResult denied = verifiable().run();
        denied.assertRefused();
        assertTrue(denied.file("output.json").contains("HTTP 403"), denied.file("output.json"));
        assertTrue(denied.file("output.json").contains("no storage.objects.create"),
                denied.file("output.json"));
        assertTrue(denied.file("output.json").contains("\"errorType\":1"),
                "403 is USER (1): " + denied.file("output.json"));

        stub.uploadStatus = 500;
        stub.uploadBody = "{\"error\":{\"message\":\"backend exploded\"}}";
        AtomResult broken = verifiable().run();
        broken.assertRefused();
        assertTrue(broken.file("output.json").contains("\"errorType\":2"),
                "500 is THIRD_PART (2): " + broken.file("output.json"));

        stub.uploadStatus = 404;
        AtomResult missingBucket = verifiable().run();
        missingBucket.assertRefused();
        assertTrue(missingBucket.file("output.json").contains("\"errorType\":1"),
                "404 is USER (1) here: " + missingBucket.file("output.json"));
    }

    @Test
    @DisplayName("failOnError=false collects the failures, keeps going, and reports both counts")
    void keepsGoingWhenAsked() throws Exception {
        stub.uploadStatus = 500;
        stub.uploadBody = "{\"error\":{\"message\":\"nope\"}}";
        AtomResult run = verifiable()
                .file("build/libs/second.jar", "y")
                .input("files", "build/libs/*.jar")
                .input("failOnError", "false")
                .run();

        run.assertOk();
        assertEquals("0", run.field("uploaded"), run.file("output.json"));
        assertEquals("2", run.field("failed"), run.file("output.json"));
        assertEquals("0", run.field("bytes"), run.file("output.json"));
        assertEquals("", run.field("first"), "nothing was uploaded, so there is no first object");
        assertEquals(2, stub.uploads().size(), "the second file was not tried: " + stub.uploads());
        assertTrue(run.console().contains("warning: HTTP 500"), run.console());
    }

    @Test
    @DisplayName("a 2xx without an object body still counts, and the url falls back to gs://bucket/name")
    void acceptsAnEmptyAcknowledgement() throws Exception {
        stub.uploadBody = "";
        AtomResult run = upload("releases").run();

        run.assertOk();
        assertEquals("1", run.field("uploaded"), run.file("output.json"));
        assertEquals("gs://acme-artifacts/releases/app-1.0.0.jar", run.field("first"),
                run.file("output.json"));
        assertEquals("gs://acme-artifacts/releases/app-1.0.0.jar", run.field("urls"), run.file("output.json"));
    }

    @Test
    @DisplayName("more than twenty objects are all uploaded, but the urls output stops at twenty")
    void capsTheUrlsOutput() throws Exception {
        Atom a = atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("files", "many/*.txt")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url());
        for (int i = 1; i <= 22; i++) {
            a = a.file("many/file-" + i + ".txt", "line " + i);
        }
        AtomResult run = a.run();

        run.assertOk();
        assertEquals("22", run.field("uploaded"), run.file("output.json"));
        assertEquals(22, stub.uploads().size());
        assertEquals(20, run.field("urls").split("\n").length,
                "the urls output is not capped at twenty:\n" + run.field("urls"));
    }

    @Test
    @DisplayName("a long refusal body is cut, so the error message stays readable")
    void cutsALongRefusalBody() throws Exception {
        stub.uploadStatus = 400;
        stub.uploadBody = "{\"error\":{\"message\":\"" + "detail ".repeat(80) + "\"}}";
        AtomResult run = verifiable().run();

        run.assertRefused();
        String message = run.field("error");
        if (message.isEmpty()) {
            message = run.file("output.json");
        }
        assertTrue(message.contains("…"), "the body was not abbreviated:\n" + message);
        assertTrue(message.length() < 600, "the message was not cut:\n" + message);
    }

    /** The default case: a credential, one jar, the stub's endpoints. */
    private Atom verifiable() {
        return atom.file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .file("build/libs/app-1.0.0.jar", "jar-bytes")
                .input("bucket", "acme-artifacts")
                .input("clientEmail", "ci@acme.iam.gserviceaccount.com")
                .input("tokenUrl", stub.url() + "/token")
                .input("uploadUrl", stub.url());
    }
}
