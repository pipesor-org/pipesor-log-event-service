package org.pipesor.logevent.evidence.infrastructure.authority;

import com.sun.net.httpserver.HttpsConfigurator;
import com.sun.net.httpserver.HttpsServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.time.Clock;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.TrustManagerFactory;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority.Decision;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceV2;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HttpPipelineAuthorityTest {
    @TempDir Path scratch;

    @Test
    void bindsEveryCallOverTlsAndRejectsUnusableResponses() throws Exception {
        var context = tlsContext();
        var mapper = JsonMapper.builder().build();
        var requests = new ArrayList<String>();
        var server = HttpsServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        server.setHttpsConfigurator(new HttpsConfigurator(context));
        server.createContext("/internal/v1/evidence/operational-reference-checks", exchange -> {
            try (exchange) {
                var body = mapper.readTree(exchange.getRequestBody().readAllBytes());
                var trace = exchange.getRequestHeaders().getFirst("X-Correlation-Id");
                assertThat(exchange.getRequestMethod()).isEqualTo("POST");
                assertThat(exchange.getRequestHeaders().getFirst("Authorization")).isEqualTo("Bearer synthetic-token");
                assertThat(body.get("correlationId").asString()).isEqualTo(trace);
                assertThat(body.get("githubRepositoryId").asString()).isEqualTo("92233720368547758081234567");
                assertThat(body.get("runAttempt").intValue()).isEqualTo(1);
                assertThat(body.size()).isEqualTo(14);
                var requestId = body.get("requestId").asString();
                int index = requests.size();
                requests.add(requestId);
                String decision = List.of("NOT_READY", "AUTHORIZED", "DENIED", "MISMATCH", "AUTHORIZED",
                        "AUTHORIZED", "AUTHORIZED", "UNKNOWN", "AUTHORIZED").get(index);
                var reply = mapper.createObjectNode().put("requestId", index == 4 ? "wrong" : requestId)
                        .put("correlationId", trace).put("decision", decision);
                if (index == 5) reply.put("unexpected", "value");
                byte[] bytes = index == 6 ? new byte[1025] : mapper.writeValueAsBytes(reply);
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.getResponseHeaders().set("Cache-Control", "no-store");
                exchange.sendResponseHeaders(index == 8 ? 503 : 200, bytes.length);
                exchange.getResponseBody().write(bytes);
            }
        });
        server.start();
        try {
            var uri = URI.create("https://127.0.0.1:" + server.getAddress().getPort());
            try (var http = HttpClient.newBuilder().sslContext(context).build()) {
                var client = new HttpPipelineAuthority(http, uri, remaining -> "synthetic-token",
                        Clock.systemUTC(), Duration.ofSeconds(5), 1024);
                var event = event();
                var refs = refs(event);
                for (var expected : List.of(Decision.NOT_READY, Decision.AUTHORIZED, Decision.DENIED, Decision.MISMATCH,
                        Decision.UNAVAILABLE, Decision.UNAVAILABLE, Decision.UNAVAILABLE, Decision.UNAVAILABLE,
                        Decision.UNAVAILABLE)) {
                    assertThat(client.verify(event.binding(), refs, event.input().correlationId())).isEqualTo(expected);
                }
                assertThat(requests).hasSize(9).doesNotHaveDuplicates();
            }
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rejectsAnInsecureOriginAndAnAlreadyExhaustedBudget() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new HttpPipelineAuthority(URI.create("http://localhost"),
                budget -> "synthetic-token", Duration.ofSeconds(1), 1024));
        var authority = new HttpPipelineAuthority(URI.create("https://localhost"),
                budget -> { throw new AssertionError("Expired budget must stop before token acquisition"); },
                Duration.ofNanos(1), 1024);
        var event = event();
        assertThat(authority.verify(event.binding(), refs(event), event.input().correlationId())).isEqualTo(Decision.UNAVAILABLE);
    }

    private static EvidenceMembershipQuery refs(ProtectedEvidenceV2 event) {
        return new EvidenceMembershipQuery(event.input().evidenceId(), event.input().incidentId(),
                event.input().executionId(), event.input().source());
    }

    private static ProtectedEvidenceV2 event() throws Exception {
        try (var fixture = HttpPipelineAuthorityTest.class.getResourceAsStream("/protected-workflow-evidence-v2.json")) {
            var body = fixture.readAllBytes();
            return ProtectedEvidenceV2.decode(body, body.length, "cf6b69cf-a28d-49f3-bceb-000000000001",
                    "ci-investigation-204", "protected_workflow_evidence", 2);
        }
    }

    private SSLContext tlsContext() throws Exception {
        Path storePath = scratch.resolve("local-test.p12");
        var password = "synthetic-password";
        var keytool = Path.of(System.getProperty("java.home"), "bin", "keytool");
        Process process = new ProcessBuilder(keytool.toString(), "-genkeypair", "-alias", "local-test", "-keyalg",
                "RSA", "-keysize", "2048", "-dname", "CN=local-test", "-ext", "SAN=ip:127.0.0.1",
                "-validity", "1", "-storetype", "PKCS12", "-keystore", storePath.toString(),
                "-storepass", password, "-noprompt").redirectErrorStream(true).start();
        var output = process.getInputStream().readAllBytes();
        assertThat(process.waitFor()).withFailMessage(new String(output, StandardCharsets.UTF_8)).isZero();
        var store = KeyStore.getInstance("PKCS12");
        try (var stream = Files.newInputStream(storePath)) {
            store.load(stream, password.toCharArray());
        }
        var keys = KeyManagerFactory.getInstance(KeyManagerFactory.getDefaultAlgorithm());
        keys.init(store, password.toCharArray());
        var trust = TrustManagerFactory.getInstance(TrustManagerFactory.getDefaultAlgorithm());
        trust.init(store);
        var ssl = SSLContext.getInstance("TLS");
        ssl.init(keys.getKeyManagers(), trust.getTrustManagers(), null);
        return ssl;
    }
}
