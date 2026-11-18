package org.pipesor.logevent.evidence;

import static org.junit.jupiter.api.Assertions.*;

import java.time.Instant;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.NullAndEmptySource;
import org.junit.jupiter.params.provider.ValueSource;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.domain.model.valueobjects.PipelineStage;

class EvidenceInputTest {
    // message_id from NLP's integrated ingestion-evidence-v2 fixture; no source logs.
    private static final UUID MESSAGE = UUID.fromString("cf6b69cf-a28d-49f3-bceb-000000000001");
    private static final UUID INCIDENT = UUID.fromString("b0000000-0000-4000-8000-000000000001");
    private static final UUID EXECUTION = UUID.fromString("e0000000-0000-4000-8000-000000000001");

    @Test
    void matchesIntegratedNlpUuid5IdentityAndPreservesProvenance() {
        var input = input("Failure [redacted]", null, null, null);
        assertEquals(UUID.fromString("e6988490-6322-590d-b48d-662b154b55d9"), input.evidenceId());
        assertEquals(5, input.evidenceId().version());
        assertEquals(INCIDENT, input.incidentId());
        assertEquals(EXECUTION, input.executionId());
        assertEquals(4294967303L, input.sequence());
        assertEquals(Instant.parse("2026-11-08T09:20:31.123456Z"), input.observedAt());
    }

    @ParameterizedTest
    @NullAndEmptySource
    @ValueSource(strings = {" ", "secret\u0000trace", "broken\uD800", "broken\uDC00"})
    void rejectsInvalidTextWithoutEchoingIt(String invalid) {
        var error = assertThrows(IllegalArgumentException.class, () -> input(invalid, null, null, null));
        assertEquals("Invalid summary", error.getMessage());
    }

    @Test
    void optionalFieldsAreNullableButRejectMalformedValuesAndNegativeSizes() {
        assertDoesNotThrow(() -> input("Minimized 🔒", null, null, null));
        assertThrows(IllegalArgumentException.class, () -> input("summary", "\u0000", null, null));
        assertThrows(IllegalArgumentException.class, () -> input("summary", null, " ", null));
        assertThrows(IllegalArgumentException.class, () -> input("summary", null, null, -1L));
    }

    @Test
    void excludesProtectedTextFromGeneratedRecordDiagnostics() {
        assertEquals("EvidenceInput[protected]", input("synthetic-protected-marker", null, null, null).toString());
    }

    @Test
    void requiresAllQueryReferencesAndSafeSource() {
        var id = input("summary", null, null, null).evidenceId();
        assertThrows(NullPointerException.class, () -> new EvidenceMembershipQuery(null, INCIDENT, EXECUTION, "github_actions"));
        assertThrows(NullPointerException.class, () -> new EvidenceMembershipQuery(id, null, EXECUTION, "github_actions"));
        assertThrows(NullPointerException.class, () -> new EvidenceMembershipQuery(id, INCIDENT, null, "github_actions"));
        assertThrows(IllegalArgumentException.class, () -> new EvidenceMembershipQuery(id, INCIDENT, EXECUTION, "unsafe source"));
    }

    static EvidenceInput input(String summary, String excerpt, String contentHash, Long sizeBytes) {
        return new EvidenceInput(MESSAGE, INCIDENT, EXECUTION, "corr-fixture", "github_actions",
                PipelineStage.INFRASTRUCTURE, "job-[redacted]", summary, excerpt,
                Instant.parse("2026-11-08T09:20:31.123456789Z"), 4294967303L, contentHash, sizeBytes);
    }
}
