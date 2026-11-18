package org.pipesor.logevent.evidence.interfaces.rest;

import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.net.Socket;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.interfaces.RSAPublicKey;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.Executors;
import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.flywaydb.core.Flyway;
import org.postgresql.ds.PGSimpleDataSource;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.pipesor.logevent.evidence.domain.model.valueobjects.PipelineStage;
import org.pipesor.logevent.evidence.infrastructure.persistence.jdbc.JdbcEvidenceStore;
import org.testcontainers.postgresql.PostgreSQLContainer;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import tools.jackson.databind.json.JsonMapper;
import tools.jackson.databind.node.ObjectNode;

import static org.assertj.core.api.Assertions.assertThat;

class EvidenceMembershipHttpHandlerTest {
    private static final JsonMapper JSON = JsonMapper.builder().build();
    private static final URI ISSUER = URI.create("https://identity.test/workloads/v2.0");
    private static final UUID DIRECTORY = UUID.fromString("287f56c0-255d-45f4-a49c-7ea7e3bec987");
    private static final UUID CLIENT = UUID.fromString("e6edf15b-7744-4921-8fd3-6c8d6d08505e");
    private static final UUID PRINCIPAL = UUID.fromString("a8c7f0bb-71d8-4fd8-9dc7-bd8a25f8f073");
    private static final UUID TENANT = UUID.fromString("9e170a48-cd89-4ea8-8c9c-5d578d8c1687");
    private static final String INSTALLATION = "7710600000000000000000000";
    private static final String ROLE = "Correlation.EvidenceMembership.Check";
    private static final String TRACE = "membership-http-test";
    private static final KeyPair KEYS = keys();

    @Test
    void validatesTheWholeSignedCallerBeforeAnyScopedStoreLookup() throws Exception {
        try (var api = new Api()) {
            assertThat(api.post(body(), null).statusCode()).isEqualTo(401);
            assertThat(api.post(body(), token(Map.of("aud", "wrong-api"))).statusCode()).isEqualTo(401);
            assertThat(api.post(body(), token(Map.of("scp", "Human.Read"))).statusCode()).isEqualTo(401);
            assertThat(api.post(body(), token(Map.of("oid", UUID.randomUUID().toString()))).statusCode()).isEqualTo(403);
            assertThat(api.post(body(), token(Map.of("roles", List.of("Wrong")))).statusCode()).isEqualTo(403);
            assertThat(api.reads).hasValue(0);
            var request = body();
            var reply = api.post(request, token(Map.of()));
            assertThat(reply.statusCode()).isEqualTo(200);
            assertThat(reply.headers().firstValue("Cache-Control")).contains("no-store");
            var decision = JSON.readTree(reply.body());
            assertThat(decision.get("requestId").asString()).isEqualTo(request.get("requestId").asString());
            assertThat(decision.get("correlationId").asString()).isEqualTo(TRACE);
            assertThat(decision.get("decision").asString()).isEqualTo("AUTHORIZED");
            assertThat(decision.propertyNames()).containsExactlyInAnyOrder("requestId", "correlationId", "decision");
            assertThat(api.last.get().scope().tenantId()).isEqualTo(TENANT);
            assertThat(api.last.get().scope().installationId()).isEqualTo(INSTALLATION);
            assertThat(api.reads).hasValue(1);
        }
    }

    @Test
    void returnsOnlyScopedBusinessDecisionsAndNoExistenceOnScopeDenial() throws Exception {
        try (var api = new Api()) {
            var token = token(Map.of());
            for (var mutation : List.of(
                    body().put("tenantId", UUID.randomUUID().toString()),
                    body().put("githubInstallationId", "77107"))) {
                var response = api.post(mutation, token);
                assertThat(response.statusCode()).isEqualTo(200);
                assertThat(JSON.readTree(response.body()).get("decision").asString()).isEqualTo("DENIED");
            }
            assertThat(api.reads).hasValue(0);
            api.outcome.set(EvidenceStore.Membership.NOT_READY);
            assertThat(JSON.readTree(api.post(body(), token).body()).get("decision").asString()).isEqualTo("NOT_READY");
            api.outcome.set(EvidenceStore.Membership.MISMATCH);
            assertThat(JSON.readTree(api.post(body(), token).body()).get("decision").asString()).isEqualTo("MISMATCH");
            assertThat(api.reads).hasValue(2);
        }
    }

    @Test
    void rejectsAmbiguousOrLateRequestsWithoutSensitiveProblems() throws Exception {
        try (var api = new Api()) {
            var token = token(Map.of());
            var raw = JSON.writeValueAsString(body());
            for (var malformed : List.of(raw + " {}", raw.replace("\"scopeRevision\":", "\"scopeRevision\":\"private-value\",\"scopeRevision\":"),
                    raw.replace("\"source\":\"github_actions\"", "\"source\":42"))) {
                var reply = api.post(malformed, token);
                assertThat(reply.statusCode()).isEqualTo(400);
                assertThat(reply.body()).doesNotContain("private-value", TENANT.toString());
            }
            assertThat(api.post(body().put("correlationId", "crossed"), token).statusCode()).isEqualTo(400);
            assertThat(api.post(body().put("source", "other"), token).statusCode()).isEqualTo(400);
            assertThat(api.post(body().put("deadlineAt", Instant.now().minusSeconds(1).toString()), token).statusCode()).isEqualTo(503);
            assertThat(api.post(raw + " ".repeat(2048), token).statusCode()).isEqualTo(413);
            assertThat(api.reads).hasValue(0);
        }
    }

    @Test
    void refusesConfirmationAfterTheMonotonicDeadlineEvenWithAFixedWallClock() throws Exception {
        Instant now = Instant.now();
        try (var api = new Api(Clock.fixed(now, java.time.ZoneOffset.UTC))) {
            api.beforeRead.set(() -> {
                try { Thread.sleep(300); }
                catch (InterruptedException stopped) { Thread.currentThread().interrupt(); }
            });
            var reply = api.post(body().put("deadlineAt", now.plusMillis(200).toString()),
                    token(Map.of("iat", Date.from(now))));
            assertThat(reply.statusCode()).isEqualTo(503);
            assertThat(api.reads).hasValue(1);
        }
    }

    @Test
    void closesSlowRequestBodyAndRecoversAdmission() throws Exception {
        try (var api = new Api(); var socket = new Socket("127.0.0.1", api.server.getAddress().getPort())) {
            socket.setSoTimeout(6000);
            var request = "POST " + EvidenceMembershipHttpHandler.PATH + " HTTP/1.1\r\nHost: localhost\r\n"
                    + "Authorization: Bearer " + token(Map.of()) + "\r\nX-Correlation-Id: " + TRACE
                    + "\r\nContent-Type: application/json\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n1\r\n{\r\n";
            socket.getOutputStream().write(request.getBytes(StandardCharsets.US_ASCII));
            socket.getOutputStream().flush();
            var reader = new java.io.BufferedReader(new java.io.InputStreamReader(socket.getInputStream(), StandardCharsets.US_ASCII));
            assertThat(reader.readLine()).contains("503");
            socket.close();
            HttpResponse<String> response = null;
            for (int i = 0; i < 20; i++) {
                response = api.post(body(), token(Map.of()));
                if (response.statusCode() != 429) break;
                Thread.sleep(20);
            }
            assertThat(response.statusCode()).isEqualTo(200);
            assertThat(api.reads).hasValue(1);
        }
    }

    @Test
    void signedMembershipRequestQueriesTheRealScopedEvidenceTable() throws Exception {
        try (var database = new PostgreSQLContainer("postgres:17.11")) {
            database.start();
            var source = new PGSimpleDataSource();
            source.setURL(database.getJdbcUrl());
            source.setUser(database.getUsername());
            source.setPassword(database.getPassword());
            Flyway.configure().dataSource(source).defaultSchema("evidence").load().migrate();
            var store = new JdbcEvidenceStore(source, Clock.systemUTC());
            var request = body();
            var input = new EvidenceInput(UUID.randomUUID(), UUID.fromString(request.get("incidentId").asString()),
                    UUID.fromString(request.get("executionId").asString()), TRACE, "github_actions",
                    PipelineStage.TESTING, null, "Protected fixture", null, Instant.now(), null, null, null,
                    new EvidenceScope(TENANT, INSTALLATION, "scope-r1"));
            request.put("evidenceId", input.evidenceId().toString());
            try (var api = new Api(Clock.systemUTC(), store)) {
                var credential = token(Map.of());
                assertThat(JSON.readTree(api.post(request, credential).body()).get("decision").asString()).isEqualTo("NOT_READY");
                assertThat(store.register(input)).isEqualTo(EvidenceStore.Registration.CREATED);
                assertThat(JSON.readTree(api.post(request, credential).body()).get("decision").asString()).isEqualTo("AUTHORIZED");
                for (var crossed : List.of(
                        request.deepCopy().put("executionId", UUID.randomUUID().toString()),
                        request.deepCopy().put("scopeRevision", "scope-r2"))) {
                    assertThat(JSON.readTree(api.post(crossed, credential).body()).get("decision").asString()).isEqualTo("NOT_READY");
                }
            }
        }
    }

    private static ObjectNode body() {
        return JSON.createObjectNode().put("requestId", UUID.randomUUID().toString()).put("correlationId", TRACE)
                .put("deadlineAt", Instant.now().plusSeconds(10).toString()).put("tenantId", TENANT.toString())
                .put("githubInstallationId", INSTALLATION).put("scopeRevision", "scope-r1")
                .put("evidenceId", "d1865b5f-8d6f-4e75-b0ef-591f7d96f7a1")
                .put("executionId", "9be95ceb-f2bd-4295-a8c9-b0c5183b9994")
                .put("incidentId", "a0327c5c-a5ae-4552-8da5-2c1ac2ce65f6").put("source", "github_actions");
    }

    private static String token(Map<String, Object> overrides) throws Exception {
        var claims = new JWTClaimsSet.Builder().issuer(ISSUER.toString()).audience("logevent-api")
                .claim("tid", DIRECTORY.toString()).claim("oid", PRINCIPAL.toString()).claim("azp", CLIENT.toString())
                .claim("roles", List.of(ROLE)).claim("ver", "2.0").claim("idtyp", "app")
                .issueTime(new Date()).expirationTime(Date.from(Instant.now().plusSeconds(120)));
        overrides.forEach(claims::claim);
        var signed = new SignedJWT(new JWSHeader(JWSAlgorithm.RS256), claims.build());
        signed.sign(new RSASSASigner(KEYS.getPrivate()));
        return signed.serialize();
    }

    private static KeyPair keys() {
        try { var generator = KeyPairGenerator.getInstance("RSA"); generator.initialize(2048); return generator.generateKeyPair(); }
        catch (Exception unavailable) { throw new IllegalStateException(unavailable); }
    }

    private static final class Api implements AutoCloseable, EvidenceStore {
        final AtomicInteger reads = new AtomicInteger();
        final AtomicReference<EvidenceMembershipQuery> last = new AtomicReference<>();
        final AtomicReference<Membership> outcome = new AtomicReference<>(Membership.MATCH);
        final AtomicReference<Runnable> beforeRead = new AtomicReference<>(() -> {});
        final HttpServer server;
        final java.util.concurrent.ExecutorService requests = Executors.newVirtualThreadPerTaskExecutor();
        final HttpClient http = HttpClient.newHttpClient();
        final EvidenceMembershipHttpHandler handler;
        final URI uri;

        Api() throws Exception { this(Clock.systemUTC()); }

        Api(Clock clock) throws Exception { this(clock, null); }

        Api(Clock clock, EvidenceStore store) throws Exception {
            var settings = new EvidenceMembershipHttpHandler.Settings(ISSUER, URI.create("https://identity.test/keys"),
                    "logevent-api", DIRECTORY, CLIENT, PRINCIPAL, ROLE, TENANT, INSTALLATION,
                    Duration.ZERO, Duration.ofSeconds(2), 2048, 4096, 1);
            var decoder = NimbusJwtDecoder.withPublicKey((RSAPublicKey) KEYS.getPublic()).build();
            handler = new EvidenceMembershipHttpHandler(store == null ? this : store, settings, decoder, clock);
            server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
            server.setExecutor(requests);
            server.createContext(EvidenceMembershipHttpHandler.PATH, handler);
            server.start();
            uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort() + EvidenceMembershipHttpHandler.PATH);
        }

        HttpResponse<String> post(ObjectNode body, String token) throws Exception { return post(JSON.writeValueAsString(body), token); }

        HttpResponse<String> post(String body, String token) throws Exception {
            var request = HttpRequest.newBuilder(uri).timeout(Duration.ofSeconds(5))
                    .header("Content-Type", "application/json").header("X-Correlation-Id", TRACE);
            if (token != null) request.header("Authorization", "Bearer " + token);
            return http.send(request.POST(HttpRequest.BodyPublishers.ofString(body)).build(), HttpResponse.BodyHandlers.ofString());
        }

        @Override public Registration register(EvidenceInput input) { throw new AssertionError("read-only receiver"); }

        @Override public Membership membership(EvidenceMembershipQuery query) {
            reads.incrementAndGet();
            last.set(query);
            beforeRead.get().run();
            return outcome.get();
        }

        @Override public void close() { server.stop(0); handler.close(); requests.shutdownNow(); http.close(); }
    }
}
