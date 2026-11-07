package atom;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.jenkinschina.atom.sdk.Json;
import com.jenkinschina.atom.sdk.testing.Atom;
import com.jenkinschina.atom.sdk.testing.AtomResult;
import java.net.ServerSocket;
import java.net.Socket;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.util.ArrayList;
import java.util.Base64;
import java.util.List;
import java.util.Map;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

/**
 * The gcs-upload atom, started the way the runner starts it, against the token/upload fake in {@code tools/}.
 *
 * <p>These are the checks {@code tools/smoke.sh} made: the RS256 assertion really verifies (the fake checks the
 * signature with the public half of the key), the claims it carries, the object name with and without a prefix, a
 * refused token exchange, an unparsable key, and a missing input.
 */
class GcsUploadIT {

    private static KeyPair keys;
    private static Path publicKey;
    private static String privatePem;

    private Path module;
    private Path scratch;
    private final List<Process> servers = new ArrayList<>();
    private int port;
    private Path log;

    @BeforeAll
    static void generateKey() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        keys = generator.generateKeyPair();
        privatePem = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(keys.getPrivate().getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
    }

    @BeforeEach
    void setUp() throws Exception {
        module = Path.of(System.getProperty("atom.module", System.getProperty("user.dir")));
        scratch = Path.of(System.getProperty("atom.scratch", "target"));
        publicKey = Files.createTempFile(scratch, "gcs", ".pub");
        Files.writeString(publicKey, "-----BEGIN PUBLIC KEY-----\n"
                + Base64.getMimeEncoder(64, "\n".getBytes(StandardCharsets.US_ASCII))
                        .encodeToString(keys.getPublic().getEncoded())
                + "\n-----END PUBLIC KEY-----\n");
        start();
    }

    @AfterEach
    void tearDown() {
        servers.forEach(Process::destroy);
    }

    @Test
    @DisplayName("the RS256 assertion verifies, its claims are right, and the object is uploaded once")
    void uploadsWithAVerifiedAssertion() throws Exception {
        AtomResult run = upload(Atom.of(), "1.0.0");

        run.assertOk();
        assertEquals("1", run.field("uploaded"), run.file("output.json"));
        assertEquals("9", run.field("bytes"), run.file("output.json"));

        Map<String, Object> token = last("/token");
        assertEquals(Boolean.TRUE, token.get("signatureOk"), "the assertion did not verify: " + token);
        @SuppressWarnings("unchecked")
        Map<String, Object> claims = (Map<String, Object>) token.get("claims");
        assertEquals("ci@acme.iam.gserviceaccount.com", claims.get("iss"), String.valueOf(claims));
        assertTrue(String.valueOf(claims.get("scope")).endsWith("devstorage.read_write"), String.valueOf(claims));
        assertTrue(String.valueOf(claims.get("aud")).startsWith("http://127.0.0.1:"), String.valueOf(claims));
        assertTrue(String.valueOf(claims.get("aud")).endsWith("/token"), String.valueOf(claims));

        Map<String, Object> upload = last("/upload/");
        assertEquals("media", upload.get("uploadType"), String.valueOf(upload));
        assertEquals("1.0.0/app-1.0.0.jar", upload.get("name"), String.valueOf(upload));
        assertEquals("Bearer ya29.fake-token", upload.get("authorization"), String.valueOf(upload));
        assertEquals("9", String.valueOf(upload.get("size")), String.valueOf(upload));
    }

    @Test
    @DisplayName("without a prefix the workspace-relative path is the object name")
    void usesTheRelativePathWithoutAPrefix() throws Exception {
        upload(Atom.of(), "").assertOk();

        Map<String, Object> upload = last("/upload/");
        assertEquals("build/libs/app-1.0.0.jar", upload.get("name"), String.valueOf(upload));
    }

    @Test
    @DisplayName("a refused token exchange is a credential problem and says why")
    void reportsARefusedToken() throws Exception {
        restart("--refuse-token", "Invalid JWT: audience mismatch");
        AtomResult run = upload(Atom.of(), "");

        run.assertRefused();
        assertTrue(run.file("output.json").contains("audience mismatch"),
                "the refusal reason is missing: " + run.file("output.json"));
        assertTrue(run.file("output.json").contains("\"errorType\":1"),
                "a 400 from the token endpoint should be USER(1): " + run.file("output.json"));
    }

    @Test
    @DisplayName("a broken key never reaches the network")
    void refusesAnUnparsableKey() throws Exception {
        AtomResult run = uploadWithKey(Atom.of(), "", "[REDACTED PRIVATE KEY]");

        run.assertRefused();
        assertTrue(run.file("output.json").contains("could not sign the assertion"), run.file("output.json"));
    }

    @Test
    @DisplayName("a missing bucket is refused by name")
    void refusesAMissingBucket() throws Exception {
        String input = input("").replace("{\"bucket\": \"acme-artifacts\", ", "{");
        AtomResult run = Atom.of()
                .file("build/libs/app-1.0.0.jar", "jar-bytes")
                .file(".secrets.json", Json.write(Map.of("privateKey", privatePem)))
                .input(input)
                .run();

        run.assertRefused();
        assertTrue(run.file("output.json").contains("bucket is required"), run.file("output.json"));
    }

    private AtomResult upload(Atom atom, String prefix) throws Exception {
        return uploadWithKey(atom, prefix, privatePem);
    }

    private AtomResult uploadWithKey(Atom atom, String prefix, String pem) throws Exception {
        return atom.file("build/libs/app-1.0.0.jar", "jar-bytes")
                .file(".secrets.json", Json.write(Map.of("privateKey", pem)))
                .input(input(prefix))
                .run();
    }

    private String input(String prefix) {
        String extra = prefix.isEmpty() ? "" : ", \"objectPrefix\": \"" + prefix + "\"";
        return """
                {"bucket": "acme-artifacts", "clientEmail": "ci@acme.iam.gserviceaccount.com",
                 "tokenUrl": "%s/token", "uploadUrl": "%s",
                 "files": "build/libs/*.jar"%s}
                """.formatted("http://127.0.0.1:" + port, "http://127.0.0.1:" + port, extra);
    }

    private Map<String, Object> last(String pathPrefix) throws Exception {
        Map<String, Object> found = null;
        for (String line : Files.readAllLines(log)) {
            Map<String, Object> record = Json.parseObject(line);
            if (String.valueOf(record.get("path")).startsWith(pathPrefix)) {
                found = record;
            }
        }
        assertTrue(found != null, "no request to " + pathPrefix + " in " + Files.readString(log));
        return found;
    }

    private void restart(String... args) throws Exception {
        start(args);
    }

    private void start(String... args) throws Exception {
        port = freePort();
        log = Files.createTempFile(scratch, "fake-gcs", ".log");
        List<String> command = new ArrayList<>(List.of("python3",
                module.resolve("tools/fake_gcs.py").toString(),
                String.valueOf(port), log.toString(), publicKey.toString()));
        command.addAll(List.of(args));
        servers.add(new ProcessBuilder(command).redirectErrorStream(true)
                .redirectOutput(ProcessBuilder.Redirect.DISCARD).start());
        awaitPort(port);
    }

    private static int freePort() throws Exception {
        try (ServerSocket socket = new ServerSocket(0)) {
            return socket.getLocalPort();
        }
    }

    private static void awaitPort(int port) throws Exception {
        for (int i = 0; i < 200; i++) {
            try (Socket socket = new Socket("127.0.0.1", port)) {
                return;
            } catch (Exception notYet) {
                Thread.sleep(50);
            }
        }
        throw new IllegalStateException("the fake GCS did not listen on " + port);
    }
}
