package org.pipesor.logevent.evidence.application.commands;

import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;
import org.pipesor.logevent.evidence.domain.model.valueobjects.PipelineStage;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.pipesor.logevent.evidence.domain.services.EvidenceIdentity;

/**
 * Internal input: summary/excerpt/job must already be protected and minimized.
 * Shape validation is not a sanitizer and does not authorize ingestion of raw logs.
 * observedAt is truncated to PostgreSQL's microsecond precision; replay comparison
 * uses these persisted fields, not byte equality of source messages.
 */
public record EvidenceInput(
        UUID messageId, UUID incidentId, UUID executionId, String correlationId,
        String source, PipelineStage stage, String job, String summary, String excerpt,
        Instant observedAt, Long sequence, String contentHash, Long sizeBytes, EvidenceScope scope) {

    /** Compatibility for isolated legacy callers. Registration intake supplies an explicit scope. */
    public EvidenceInput(UUID messageId, UUID incidentId, UUID executionId, String correlationId,
            String source, PipelineStage stage, String job, String summary, String excerpt,
            Instant observedAt, Long sequence, String contentHash, Long sizeBytes) {
        this(messageId, incidentId, executionId, correlationId, source, stage, job, summary, excerpt,
                observedAt, sequence, contentHash, sizeBytes, null);
    }

    public EvidenceInput {
        Objects.requireNonNull(messageId, "messageId");
        Objects.requireNonNull(incidentId, "incidentId");
        Objects.requireNonNull(executionId, "executionId");
        requireSafeId(correlationId, "correlationId");
        requireSafeId(source, "source");
        Objects.requireNonNull(stage, "stage");
        requireText(summary, "summary");
        optionalText(job, "job");
        optionalText(excerpt, "excerpt");
        optionalText(contentHash, "contentHash");
        observedAt = Objects.requireNonNull(observedAt, "observedAt").truncatedTo(ChronoUnit.MICROS);
        if (sequence != null && sequence < 0) {
            throw new IllegalArgumentException("Invalid sequence");
        }
        if (sizeBytes != null && sizeBytes < 0) {
            throw new IllegalArgumentException("Invalid sizeBytes");
        }
    }

    public UUID evidenceId() {
        return EvidenceIdentity.forMessage(messageId);
    }

    public static void requireSafeId(String value, String field) {
        if (value == null || !value.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new IllegalArgumentException("Invalid " + field);
        }
    }

    private static void optionalText(String value, String field) {
        if (value != null) requireText(value, field);
    }

    private static void requireText(String value, String field) {
        if (value == null || value.isBlank()) throw new IllegalArgumentException("Invalid " + field);
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            if (current == 0 || Character.isLowSurrogate(current)) {
                throw new IllegalArgumentException("Invalid " + field);
            }
            if (Character.isHighSurrogate(current)
                    && (++i == value.length() || !Character.isLowSurrogate(value.charAt(i)))) {
                throw new IllegalArgumentException("Invalid " + field);
            }
        }
    }

    @Override
    public String toString() {
        return "EvidenceInput[protected]";
    }
}
