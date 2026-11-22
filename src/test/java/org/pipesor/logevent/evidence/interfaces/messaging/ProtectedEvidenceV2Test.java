package org.pipesor.logevent.evidence.interfaces.messaging;

import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import tools.jackson.databind.json.JsonMapper;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class ProtectedEvidenceV2Test {
    private static final String MESSAGE = "cf6b69cf-a28d-49f3-bceb-000000000001";
    private static final String TRACE = "ci-investigation-204";
    private static final String TYPE = "protected_workflow_evidence";

    @Test
    void preservesActualProducerBindingAndMapsOnlyOwnedEvidenceFields() throws Exception {
        byte[] body = fixture();
        var event = ProtectedEvidenceV2.decode(body, body.length, MESSAGE, TRACE, TYPE, 2);
        assertThat(event.input().evidenceId()).isEqualTo(UUID.fromString("e6988490-6322-590d-b48d-662b154b55d9"));
        assertThat(event.binding().pipelineId()).isEqualTo(UUID.fromString("b2e4adde-f9ef-54c8-b00f-7914af19efde"));
        assertThat(event.binding().githubRepositoryId()).isEqualTo("92233720368547758081234567");
        assertThat(event.binding().githubRunId()).isEqualTo("999999999999999999999999999");
        assertThat(event.binding().runAttempt()).isEqualTo(1);
        assertThat(event.binding().occurredAt()).isEqualTo(Instant.parse("2026-11-08T09:20:31.123456789Z"));
        assertThat(event.binding().sourceUpdatedAt()).isEqualTo(Instant.parse("2026-11-08T09:20:40.987654321Z"));
        assertThat(event.input().observedAt()).isEqualTo(Instant.parse("2026-11-08T09:20:31.123456Z"));
        assertThat(event.input().sequence()).isEqualTo(4294967303L);
        assertThat(event.input().contentHash()).isNull();
        assertThat(event.input().sizeBytes()).isNull();
        assertThat(event.toString()).doesNotContain("Trace [redacted]", MESSAGE);
        assertThat(event.binding().toString()).doesNotContain("scope-rev-12", "92233720368547758081234567");
    }

    @Test
    void aggregateLocatorIncludesOriginalExecutionAndRequiresMatchingJob() throws Exception {
        var mapper = JsonMapper.builder().build();
        var document = (tools.jackson.databind.node.ObjectNode) mapper.readTree(fixture());
        var evidence = (tools.jackson.databind.node.ObjectNode) document.get("evidence");
        String locator = "v2:job:701:member:0_verify.txt:lines:2-2:sha256:" + "a".repeat(64);
        document.put("schema_version", "2.1");
        evidence.put("job", "701");
        evidence.put("source_locator", locator);
        var value = decode(mapper.writeValueAsBytes(document));
        assertThat(value.input().sourceLocator()).isEqualTo(value.binding().githubRepositoryId() + ":" +
                value.binding().githubWorkflowId() + ":" + value.binding().githubRunId() + ":1:" + locator);
        evidence.put("job", "702");
        assertThrows(IllegalArgumentException.class, () -> decode(mapper.writeValueAsBytes(document)));
    }

    @Test
    void version21KeepsItsExactSingleLineVerifyRules() throws Exception {
        var digest = "b".repeat(64);
        assertThat(locator("2.1", "701", "v2:job:701:member:12_verify.txt:lines:9-9:sha256:" + digest)).isNotNull();
        for (var invalid : List.of("v2:job:701:member:12_verify.txt:lines:9-10:sha256:" + digest,
                "v2:job:701:member:build.txt:lines:9-9:sha256:" + digest)) {
            assertThrows(IllegalArgumentException.class, () -> locator("2.1", "701", invalid));
        }
    }

    @Test
    void version22AcceptsAnyEncodedMemberAndMultiLineRanges() throws Exception {
        var digest = "c".repeat(64);
        for (var valid : List.of(
                "v2:job:701:member:12_verify.txt:lines:9-9:sha256:" + digest,
                "v2:job:701:member:build%2F3_Run%20mvn%20verify.txt:lines:120-319:sha256:" + digest,
                "v2:job:99999999999999999999:member:%C3%A9tape.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:a~b-c_d.e:lines:5-6:sha256:" + digest)) {
            String job = valid.substring(7, valid.indexOf(":member:"));
            var stored = locator("2.2", job, valid);
            assertThat(stored).endsWith(":" + valid);
        }
        for (var invalid : List.of(
                "v2:job:701:member:build.txt:lines:10-9:sha256:" + digest,
                "v2:job:701:member:build.txt:lines:1-201:sha256:" + digest,
                "v2:job:702:member:build.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:build%2f1.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:%41.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:%2Fetc.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:..%2Fx.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:a%2Fb%2Fc.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:dir%2F:lines:1-1:sha256:" + digest,
                "v2:job:701:member:a%5Cb.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:a%0Ab.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:%FF.txt:lines:1-1:sha256:" + digest,
                "v2:job:701:member:" + "a".repeat(256) + ":lines:1-1:sha256:" + digest,
                "v2:job:701:member:build.txt:lines:1-1:sha256:" + "C".repeat(64),
                "v2:job:701:member:build.txt:lines:0-1:sha256:" + digest)) {
            assertThrows(IllegalArgumentException.class, () -> locator("2.2", "701", invalid), invalid);
        }
        var mapper = JsonMapper.builder().build();
        var document = (tools.jackson.databind.node.ObjectNode) mapper.readTree(fixture());
        document.put("schema_version", "2.2");
        ((tools.jackson.databind.node.ObjectNode) document.get("evidence")).put("job", "701");
        assertThrows(IllegalArgumentException.class, () -> decode(mapper.writeValueAsBytes(document)));
    }

    @Test
    void version20MustNotCarryALocator() throws Exception {
        var mapper = JsonMapper.builder().build();
        var document = (tools.jackson.databind.node.ObjectNode) mapper.readTree(fixture());
        ((tools.jackson.databind.node.ObjectNode) document.get("evidence"))
                .put("source_locator", "v2:job:701:member:build.txt:lines:1-1:sha256:" + "d".repeat(64));
        assertThrows(IllegalArgumentException.class, () -> decode(mapper.writeValueAsBytes(document)));
    }

    private static String locator(String version, String job, String locator) throws Exception {
        var mapper = JsonMapper.builder().build();
        var document = (tools.jackson.databind.node.ObjectNode) mapper.readTree(fixture());
        document.put("schema_version", version);
        var evidence = (tools.jackson.databind.node.ObjectNode) document.get("evidence");
        evidence.put("job", job);
        evidence.put("source_locator", locator);
        return decode(mapper.writeValueAsBytes(document)).input().sourceLocator();
    }

    @Test
    void acceptsNullableOrAbsentJobAndSequence() throws Exception {
        var mapper = JsonMapper.builder().build();
        var document = (tools.jackson.databind.node.ObjectNode) mapper.readTree(fixture());
        var evidence = (tools.jackson.databind.node.ObjectNode) document.get("evidence");
        evidence.putNull("job");
        evidence.putNull("sequence");
        var nullable = decode(mapper.writeValueAsBytes(document));
        assertThat(nullable.input().job()).isNull();
        assertThat(nullable.input().sequence()).isNull();
        evidence.remove("job");
        evidence.remove("sequence");
        var absent = decode(mapper.writeValueAsBytes(document));
        assertThat(absent.input()).isEqualTo(nullable.input());
    }

    @Test
    void rejectsBadMetadataAndOversizedOrMalformedInputSafely() throws Exception {
        byte[] body = fixture();
        assertThrows(IllegalArgumentException.class, () -> ProtectedEvidenceV2.decode(body, body.length - 1, MESSAGE, TRACE, TYPE, 2));
        assertThrows(IllegalArgumentException.class, () -> ProtectedEvidenceV2.decode(body, body.length, "other", TRACE, TYPE, 2));
        assertThrows(IllegalArgumentException.class, () -> ProtectedEvidenceV2.decode(body, body.length, MESSAGE, "other", TYPE, 2));
        assertThrows(IllegalArgumentException.class, () -> ProtectedEvidenceV2.decode(body, body.length, MESSAGE, TRACE, "other", 2));
        assertThrows(IllegalArgumentException.class, () -> ProtectedEvidenceV2.decode(body, body.length, MESSAGE, TRACE, TYPE, 1));
        var json = new String(body, StandardCharsets.UTF_8);
        for (var changed : List.of(json + " {}", "{\"message_id\":\"private-content\"," + json.substring(1),
                json.replace("\"2.0\"", "\"3.0\""), json.replace("4294967303", "9223372036854775808"),
                json.replace(TRACE, " " + TRACE), json.replace("\"failure\"", "\"success\""),
                json.replace("scope_revision", "unknown_scope"))) {
            var exception = assertThrows(IllegalArgumentException.class, () -> decode(changed.getBytes(StandardCharsets.UTF_8)));
            assertThat(exception.getCause()).isNull();
            assertThat(exception.getMessage()).doesNotContain("private-content", "Trace");
        }
        assertThrows(IllegalArgumentException.class, () -> decode(new byte[] {(byte) 0xc3, 0x28}));
    }

    @Test
    void keepsSeparateExecutionAndIncidentReferencesForDifferentAttempts() throws Exception {
        byte[] body = fixture();
        var first = decode(body);
        var replay = decode(new String(body, StandardCharsets.UTF_8)
                .replace("\"run_attempt\":1", "\"run_attempt\":2").getBytes(StandardCharsets.UTF_8));
        assertThat(replay.binding().runAttempt()).isEqualTo(2);
        assertThat(replay.input().executionId()).isNotEqualTo(first.input().executionId());
        assertThat(replay.input().incidentId()).isNotEqualTo(first.input().incidentId());
    }

    private static ProtectedEvidenceV2 decode(byte[] body) {
        return ProtectedEvidenceV2.decode(body, body.length, MESSAGE, TRACE, TYPE, 2);
    }

    private static byte[] fixture() throws Exception {
        try (var input = ProtectedEvidenceV2Test.class.getResourceAsStream("/protected-workflow-evidence-v2.json")) {
            return Objects.requireNonNull(input).readAllBytes();
        }
    }
}
