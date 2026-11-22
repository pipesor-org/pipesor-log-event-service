package org.pipesor.logevent;

import com.nimbusds.jose.jwk.JWKSet;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.attribute.PosixFilePermissions;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Signature;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Base64;
import java.util.List;
import java.util.UUID;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.Test;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.pipesor.logevent.evidence.domain.model.valueobjects.PipelineStage;
import org.pipesor.logevent.evidence.interfaces.rest.EvidenceMembershipController;
import org.pipesor.logevent.shared.security.SigningKey;
import org.pipesor.logevent.shared.security.WorkloadTokens;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.web.server.LocalServerPort;
import org.springframework.jdbc.core.JdbcTemplate;
import org.springframework.test.context.ActiveProfiles;
import org.springframework.test.context.DynamicPropertyRegistry;
import org.springframework.test.context.DynamicPropertySource;
import org.testcontainers.postgresql.PostgreSQLContainer;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;

/** Full runtime composition under the local profile: Flyway, platform security, routes, health and JWKS. */
@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@ActiveProfiles("local")
class LogEventApplicationTest {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final UUID TENANT = UUID.fromString("9e170a48-cd89-4ea8-8c9c-5d578d8c1687");
    private static final String INSTALLATION = "7710600000000000000000000";
    private static final String TRACE = "membership-http-test";
    private static final KeyPair SELF = rsa();
    private static final KeyPair CORRELATION = rsa();
    private static final KeyPair NLP = rsa();
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11");
    private static HttpServer jwks;
    private static Path keyDirectory;

    @LocalServerPort int port;
    @Autowired EvidenceStore store;
    @Autowired JdbcTemplate jdbc;
    private final HttpClient http = HttpClient.newHttpClient();

    @DynamicPropertySource
    static void runtime(DynamicPropertyRegistry registry) throws Exception {
        POSTGRES.start();
        jwks = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
        for (var entry : List.of(new Object[] {"correlation", CORRELATION}, new Object[] {"nlp", NLP})) {
            byte[] body = new JWKSet(key((KeyPair) entry[1]).publicJwk()).toString(true).getBytes(StandardCharsets.UTF_8);
            jwks.createContext("/" + entry[0], exchange -> {
                exchange.getResponseHeaders().set("Content-Type", "application/json");
                exchange.sendResponseHeaders(200, body.length);
                exchange.getResponseBody().write(body);
                exchange.close();
            });
        }
        jwks.start();
        keyDirectory = Files.createTempDirectory("log-event-test-keys");
        Path pem = keyDirectory.resolve("log-event.pem");
        Files.writeString(pem, "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder().encodeToString(SELF.getPrivate().getEncoded()) + "\n-----END PRIVATE KEY-----\n");
        Files.setPosixFilePermissions(pem, PosixFilePermissions.fromString("rw-------"));
        String keys = "http://127.0.0.1:" + jwks.getAddress().getPort();

        registry.add("PIPESOR_DATABASE_URL", POSTGRES::getJdbcUrl);
        registry.add("PIPESOR_DATABASE_USERNAME", POSTGRES::getUsername);
        registry.add("PIPESOR_DATABASE_PASSWORD", POSTGRES::getPassword);
        registry.add("PIPESOR_TENANT_ID", TENANT::toString);
        registry.add("PIPESOR_WORKLOAD_ID", () -> "log-event");
        registry.add("PIPESOR_SIGNING_KEY_FILE", pem::toString);
        registry.add("PIPESOR_SERVICE_BUS_CONNECTION_STRING", () -> "unused-in-test");
        registry.add("pipesor.service-bus.enabled", () -> "false");
        registry.add("management.endpoint.health.validate-group-membership", () -> "false");
        registry.add("pipesor.security.audience", () -> "urn:pipesor:api:log-event");
        registry.add("pipesor.security.trusted-workloads[0].id", () -> "correlation");
        registry.add("pipesor.security.trusted-workloads[0].jwks-uri", () -> keys + "/correlation");
        registry.add("pipesor.security.trusted-workloads[0].roles", () -> EvidenceMembershipController.ROLE);
        registry.add("pipesor.security.trusted-workloads[1].id", () -> "nlp");
        registry.add("pipesor.security.trusted-workloads[1].jwks-uri", () -> keys + "/nlp");
        registry.add("pipesor.security.trusted-workloads[1].roles", () -> "Nlp.ProcessedEvidence.Send");
        registry.add("pipesor.endpoints.pipeline", () -> "http://127.0.0.1:9");
    }

    @AfterAll
    static void stop() throws Exception {
        if (jwks != null) jwks.stop(0);
        POSTGRES.stop();
        if (keyDirectory != null) {
            try (var files = Files.list(keyDirectory)) {
                for (var file : files.toList()) Files.delete(file);
            }
            Files.delete(keyDirectory);
        }
    }

    @Test
    void migratesTheOwnedTableWithItsOwnHistoryAndReportsProbes() throws Exception {
        assertThat(jdbc.queryForList("""
                SELECT table_name FROM information_schema.tables WHERE table_schema = 'evidence' ORDER BY table_name
                """, String.class)).containsExactly("evidence_items", "flyway_history_log_event");
        assertThat(jdbc.queryForObject("SELECT count(*) FROM evidence.flyway_history_log_event WHERE success AND version = '3'",
                Integer.class)).isEqualTo(1);
        for (var probe : List.of("/actuator/health/liveness", "/actuator/health/readiness")) {
            var response = get(probe);
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(JSON.readTree(response.body()).get("status").asString()).isEqualTo("UP");
        }
        assertThat(get("/actuator/health").statusCode()).isEqualTo(401);
        assertThat(get("/actuator/env").statusCode()).isEqualTo(401);
    }

    @Test
    void publishesOnlyPublicSigningKeys() throws Exception {
        var response = get("/.well-known/jwks.json");
        assertThat(response.statusCode()).isEqualTo(200);
        assertThat(response.headers().firstValue("Cache-Control")).hasValueSatisfying(value ->
                assertThat(value).contains("max-age=300").contains("public"));
        var key = JSON.readTree(response.body()).get("keys").get(0);
        assertThat(key.get("kid").asString()).isEqualTo(key(SELF).keyId());
        assertThat(key.has("d")).isFalse();
    }

    @Test
    void acceptsOnlyCorrelationWithItsMembershipRole() throws Exception {
        var anonymous = post(body(), null);
        assertThat(anonymous.statusCode()).isEqualTo(401);
        assertThat(anonymous.headers().firstValue("Content-Type")).contains("application/problem+json");
        assertThat(anonymous.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(anonymous.headers().firstValue("WWW-Authenticate")).contains("Bearer");
        assertThat(JSON.readTree(anonymous.body()).get("code").asString()).isEqualTo("UNAUTHENTICATED");

        assertThat(post(body(), "not-a-jwt").statusCode()).isEqualTo(401);
        var repeated = http.send(HttpRequest.newBuilder(uri(EvidenceMembershipController.PATH))
                .header("Content-Type", "application/json").header("X-Correlation-Id", TRACE)
                .header("Authorization", "Bearer " + correlation()).header("Authorization", "Bearer " + correlation())
                .POST(HttpRequest.BodyPublishers.ofString(JSON.writeValueAsString(body()))).build(),
                HttpResponse.BodyHandlers.ofString());
        assertThat(repeated.statusCode()).isEqualTo(400);
        assertThat(JSON.readTree(repeated.body()).get("code").asString()).isEqualTo("INVALID_REQUEST");
        assertThat(post(body(), "with space").statusCode()).isEqualTo(400);
        var impostor = new WorkloadTokens("correlation", TENANT, key(NLP), Clock.systemUTC())
                .issue("log-event", EvidenceMembershipController.ROLE).value();
        assertThat(post(body(), impostor).statusCode()).isEqualTo(401);
        var otherAudience = new WorkloadTokens("correlation", TENANT, key(CORRELATION), Clock.systemUTC())
                .issue("pipeline", EvidenceMembershipController.ROLE).value();
        assertThat(post(body(), otherAudience).statusCode()).isEqualTo(401);
        var otherTenant = new WorkloadTokens("correlation", UUID.randomUUID(), key(CORRELATION), Clock.systemUTC())
                .issue("log-event", EvidenceMembershipController.ROLE).value();
        assertThat(post(body(), otherTenant).statusCode()).isEqualTo(401);

        var nlp = new WorkloadTokens("nlp", TENANT, key(NLP), Clock.systemUTC())
                .issue("log-event", "Nlp.ProcessedEvidence.Send").value();
        var denied = post(body(), nlp);
        assertThat(denied.statusCode()).isEqualTo(403);
        assertThat(denied.headers().firstValue("Content-Type")).contains("application/problem+json");
        assertThat(JSON.readTree(denied.body()).get("code").asString()).isEqualTo("CALLER_DENIED");

        var get = http.send(HttpRequest.newBuilder(uri(EvidenceMembershipController.PATH))
                .header("Authorization", "Bearer " + correlation()).GET().build(), HttpResponse.BodyHandlers.ofString());
        assertThat(get.statusCode()).isEqualTo(403);
    }

    @Test
    void answersScopedMembershipWithoutRevealingOtherScopes() throws Exception {
        var request = body();
        var input = new EvidenceInput(UUID.randomUUID(), UUID.fromString(request.get("incidentId").asString()),
                UUID.fromString(request.get("executionId").asString()), TRACE, "github_actions",
                PipelineStage.TESTING, null, "Protected fixture", null, Instant.now(), null, null, null,
                new EvidenceScope(TENANT, INSTALLATION, "scope-r1"));
        request.put("evidenceId", input.evidenceId().toString());
        String token = correlation();

        var pending = post(request, token);
        assertThat(pending.statusCode()).isEqualTo(200);
        assertThat(pending.headers().firstValue("Cache-Control")).contains("no-store");
        assertThat(pending.headers().firstValue("Content-Type")).contains("application/json");
        assertThat(decision(pending)).isEqualTo("NOT_READY");

        assertThat(store.register(input)).isEqualTo(EvidenceStore.Registration.CREATED);
        var matched = JSON.readTree(post(request, token).body());
        assertThat(matched.propertyNames()).containsExactlyInAnyOrder("requestId", "correlationId", "decision");
        assertThat(matched.get("requestId").asString()).isEqualTo(request.get("requestId").asString());
        assertThat(matched.get("correlationId").asString()).isEqualTo(TRACE);
        assertThat(matched.get("decision").asString()).isEqualTo("AUTHORIZED");

        for (var crossed : List.of(request.deepCopy().put("executionId", UUID.randomUUID().toString()),
                request.deepCopy().put("scopeRevision", "scope-r2"),
                request.deepCopy().put("githubInstallationId", "77107"))) {
            assertThat(decision(post(crossed, token))).isEqualTo("NOT_READY");
        }
        assertThat(decision(post(request.deepCopy().put("tenantId", UUID.randomUUID().toString()), token))).isEqualTo("DENIED");
    }

    @Test
    void rejectsMalformedOversizedOrLateRequestsWithFixedProblems() throws Exception {
        String token = correlation();
        var raw = JSON.writeValueAsString(body());
        for (var malformed : List.of(raw + " {}",
                raw.replace("\"scopeRevision\":", "\"scopeRevision\":\"private-value\",\"scopeRevision\":"),
                raw.replace("\"source\":\"github_actions\"", "\"source\":42"))) {
            var reply = post(malformed, token, "application/json", "");
            assertThat(reply.statusCode()).isEqualTo(400);
            assertThat(reply.body()).doesNotContain("private-value", TENANT.toString());
            assertThat(JSON.readTree(reply.body()).get("code").asString()).isEqualTo("INVALID_REQUEST");
        }
        assertThat(post(body().put("correlationId", "crossed"), token).statusCode()).isEqualTo(400);
        assertThat(post(body().put("source", "other"), token).statusCode()).isEqualTo(400);
        assertThat(post(raw, token, "application/json", "?x=1").statusCode()).isEqualTo(400);
        assertThat(post(raw, token, "text/plain", "").statusCode()).isEqualTo(415);
        assertThat(post(raw, token, "application/json; charset=utf-8", "").statusCode()).isEqualTo(200);
        var late = post(body().put("deadlineAt", Instant.now().minusSeconds(1).toString()), token);
        assertThat(late.statusCode()).isEqualTo(503);
        assertThat(JSON.readTree(late.body()).get("code").asString()).isEqualTo("UNAVAILABLE");
        var large = post(raw + " ".repeat(2048), token, "application/json", "");
        assertThat(large.statusCode()).isEqualTo(413);
        assertThat(large.headers().firstValue("Cache-Control")).contains("no-store");
    }

    private String decision(HttpResponse<String> response) {
        assertThat(response.statusCode()).isEqualTo(200);
        return JSON.readTree(response.body()).get("decision").asString();
    }

    private static String correlation() {
        return new WorkloadTokens("correlation", TENANT, key(CORRELATION), Clock.systemUTC())
                .issue("log-event", EvidenceMembershipController.ROLE).value();
    }

    private static ObjectNode body() {
        return JSON.createObjectNode().put("requestId", UUID.randomUUID().toString()).put("correlationId", TRACE)
                .put("deadlineAt", Instant.now().plusSeconds(10).toString()).put("tenantId", TENANT.toString())
                .put("githubInstallationId", INSTALLATION).put("scopeRevision", "scope-r1")
                .put("evidenceId", "d1865b5f-8d6f-4e75-b0ef-591f7d96f7a1")
                .put("executionId", UUID.randomUUID().toString())
                .put("incidentId", UUID.randomUUID().toString()).put("source", "github_actions");
    }

    private URI uri(String path) {
        return URI.create("http://127.0.0.1:" + port + path);
    }

    private HttpResponse<String> get(String path) throws Exception {
        return http.send(HttpRequest.newBuilder(uri(path)).timeout(Duration.ofSeconds(5)).GET().build(),
                HttpResponse.BodyHandlers.ofString());
    }

    private HttpResponse<String> post(JsonNode body, String token) throws Exception {
        return post(JSON.writeValueAsString(body), token, "application/json", "");
    }

    private HttpResponse<String> post(String body, String token, String contentType, String query) throws Exception {
        var request = HttpRequest.newBuilder(uri(EvidenceMembershipController.PATH + query)).timeout(Duration.ofSeconds(5))
                .header("Content-Type", contentType).header("X-Correlation-Id", TRACE);
        if (token != null) request.header("Authorization", "Bearer " + token);
        return http.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
    }

    private static SigningKey key(KeyPair pair) {
        return new SigningKey() {
            @Override public RSAPublicKey publicKey() { return (RSAPublicKey) pair.getPublic(); }
            @Override public byte[] sign(byte[] input) {
                try {
                    var signature = Signature.getInstance("SHA256withRSA");
                    signature.initSign(pair.getPrivate());
                    signature.update(input);
                    return signature.sign();
                } catch (Exception failure) { throw new IllegalStateException(failure); }
            }
        };
    }

    private static KeyPair rsa() {
        try {
            var generator = KeyPairGenerator.getInstance("RSA");
            generator.initialize(2048);
            return generator.generateKeyPair();
        } catch (Exception failure) { throw new IllegalStateException(failure); }
    }
}
