package org.pipesor.logevent.evidence.infrastructure.authority;

import com.sun.net.httpserver.HttpServer;
import java.net.InetSocketAddress;
import java.net.URI;
import java.time.Duration;
import java.util.ArrayList;
import java.util.List;
import org.junit.jupiter.api.Test;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority.Decision;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceV2;
import org.pipesor.logevent.shared.security.TransportPolicy;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class HttpPipelineAuthorityTest {
    private static final TransportPolicy LOCAL = TransportPolicy.forProfiles("local");
    private static final TransportPolicy AZURE = TransportPolicy.forProfiles("azure");

    @Test
    void bindsEveryCallToItsRequestAndRejectsUnusableResponses() throws Exception {
        var mapper = JsonMapper.builder().build();
        var requests = new ArrayList<String>();
        var server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
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
                        "AUTHORIZED", "AUTHORIZED", "UNKNOWN", "AUTHORIZED", "AUTHORIZED", "AUTHORIZED").get(index);
                var reply = mapper.createObjectNode().put("requestId", index == 4 ? "wrong" : requestId)
                        .put("correlationId", trace).put("decision", decision);
                if (index == 5) reply.put("unexpected", "value");
                byte[] bytes = index == 6 ? new byte[1025] : mapper.writeValueAsBytes(reply);
                exchange.getResponseHeaders().set("Content-Type", switch (index) {
                    case 1 -> "application/json;charset=UTF-8";
                    case 9 -> "application/json; charset=ISO-8859-1";
                    case 10 -> "text/plain";
                    default -> "application/json";
                });
                exchange.getResponseHeaders().set("Cache-Control", "no-store");
                exchange.sendResponseHeaders(index == 8 ? 503 : 200, bytes.length);
                exchange.getResponseBody().write(bytes);
            }
        });
        server.start();
        try {
            var uri = URI.create("http://127.0.0.1:" + server.getAddress().getPort());
            var client = new HttpPipelineAuthority(uri, remaining -> "synthetic-token", LOCAL,
                    Duration.ofSeconds(5), 1024);
            var event = event();
            var refs = refs(event);
            for (var expected : List.of(Decision.NOT_READY, Decision.AUTHORIZED, Decision.DENIED, Decision.MISMATCH,
                    Decision.UNAVAILABLE, Decision.UNAVAILABLE, Decision.UNAVAILABLE, Decision.UNAVAILABLE,
                    Decision.UNAVAILABLE, Decision.UNAVAILABLE, Decision.UNAVAILABLE)) {
                assertThat(client.verify(event.binding(), refs, event.input().correlationId())).isEqualTo(expected);
            }
            assertThat(requests).hasSize(11).doesNotHaveDuplicates();
        } finally {
            server.stop(0);
        }
    }

    @Test
    void rejectsAnInsecureOriginAndAnAlreadyExhaustedBudget() throws Exception {
        assertThrows(IllegalArgumentException.class, () -> new HttpPipelineAuthority(URI.create("http://localhost"),
                budget -> "synthetic-token", AZURE, Duration.ofSeconds(1), 1024));
        assertThrows(IllegalArgumentException.class, () -> new HttpPipelineAuthority(URI.create("http://10.0.0.4"),
                budget -> "synthetic-token", LOCAL, Duration.ofSeconds(1), 1024));
        assertThrows(IllegalArgumentException.class, () -> new HttpPipelineAuthority(URI.create("https://pipeline.example/base"),
                budget -> "synthetic-token", AZURE, Duration.ofSeconds(1), 1024));
        var authority = new HttpPipelineAuthority(URI.create("https://localhost"),
                budget -> { throw new AssertionError("Expired budget must stop before token acquisition"); },
                AZURE, Duration.ofNanos(1), 1024);
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
}
