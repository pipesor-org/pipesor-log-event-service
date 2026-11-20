package org.pipesor.logevent.evidence.interfaces.messaging;

import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.util.UUID;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.domain.model.valueobjects.PipelineStage;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.pipesor.logevent.evidence.domain.services.EvidenceIdentity;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Isolated compatibility adapter for the existing producer, pending the joint intake contract. */
public record ProtectedEvidenceV2(EvidenceInput input, Binding binding) {
    private static final String EVENT_TYPE = "protected_workflow_evidence";
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .build();

    /** Full historical binding for the caller's authority check; identities alone do not grant access. */
    public record Binding(
            UUID tenantId, String githubAccountId, String githubInstallationId,
            String githubRepositoryId, String githubWorkflowId, String githubRunId,
            int runAttempt, String scopeRevision, UUID pipelineId,
            Instant sourceUpdatedAt, Instant occurredAt, String commitSha,
            String status, String conclusion, String service, String environment) {
        @Override
        public String toString() {
            return "Binding[protected]";
        }
    }

    public static ProtectedEvidenceV2 decode(byte[] body, int maxBytes, String messageId,
            String correlationId, String eventType, int schemaMajor) {
        try {
            require(body != null && maxBytes > 0 && body.length <= maxBytes);
            require(EVENT_TYPE.equals(eventType) && schemaMajor == 2);
            String decoded = StandardCharsets.UTF_8.newDecoder()
                    .onMalformedInput(CodingErrorAction.REPORT)
                    .onUnmappableCharacter(CodingErrorAction.REPORT)
                    .decode(ByteBuffer.wrap(body)).toString();
            JsonNode root = object(JSON.readTree(decoded));
            String version = text(root, "schema_version");
            require("2.0".equals(version) || "2.1".equals(version));
            require(EVENT_TYPE.equals(text(root, "event_type")));
            UUID sourceMessageId = uuid(root, "message_id");
            String sourceCorrelationId = safeId(root, "correlation_id");
            require(sourceMessageId.toString().equals(messageId) && sourceCorrelationId.equals(correlationId));
            require("github_actions".equals(text(root, "source")));

            JsonNode capture = object(root.get("capture_context"));
            UUID tenantId = uuid(capture, "tenant_id");
            String accountId = externalId(capture, "github_account_id");
            String installationId = externalId(capture, "github_installation_id");
            String scopeRevision = safeId(capture, "scope_revision");
            JsonNode pipeline = object(root.get("pipeline"));
            String repositoryId = externalId(pipeline, "github_repository_id");
            String workflowId = externalId(pipeline, "github_workflow_id");
            JsonNode execution = object(root.get("execution"));
            String runId = externalId(execution, "github_run_id");
            JsonNode attemptNode = execution.get("run_attempt");
            require(attemptNode != null && attemptNode.isIntegralNumber() && attemptNode.canConvertToInt());
            int attempt = attemptNode.intValue();
            require(attempt > 0);
            String status = text(execution, "status");
            String conclusion = text(execution, "conclusion");
            require("completed".equals(status) && ("failure".equals(conclusion) || "timed_out".equals(conclusion)));
            String commitSha = text(object(root.get("commit")), "sha");
            require(commitSha.matches("(?:[0-9a-f]{40}|[0-9a-f]{64})"));
            Instant occurredAt = timestamp(root, "occurred_at");
            Instant sourceUpdatedAt = timestamp(root, "source_updated_at");
            String service = nullableText(root, "service", true);
            String environment = nullableText(root, "environment", true);

            UUID pipelineId = EvidenceIdentity.named("urn:pipesor:v1:pipeline:github:" + repositoryId + ":" + workflowId);
            UUID executionId = EvidenceIdentity.named("urn:pipesor:v1:execution:github:" + repositoryId + ":" + runId + ":" + attempt);
            // Derivation is a logical reference, not proof that the incident exists.
            UUID incidentId = EvidenceIdentity.named("urn:pipesor:v1:incident:" + executionId);
            JsonNode evidence = object(root.get("evidence"));
            String job = nullableText(evidence, "job", false);
            String locator = null;
            if ("2.1".equals(version)) {
                locator = text(evidence, "source_locator");
                require(job != null && job.matches("[1-9][0-9]*") && locator.matches(
                        "v2:job:" + job + ":member:[0-9]{1,9}_verify\\.txt:lines:([1-9][0-9]{0,8})-\\1:sha256:[0-9a-f]{64}"));
            } else { require(!evidence.has("source_locator")); }
            EvidenceInput input = new EvidenceInput(sourceMessageId, incidentId, executionId,
                    sourceCorrelationId, "github_actions", PipelineStage.valueOf(text(evidence, "stage")),
                    job, text(evidence, "summary"), text(evidence, "excerpt"),
                    occurredAt, sequence(evidence), null, null, new EvidenceScope(tenantId, installationId, scopeRevision),
                    locator == null ? null : repositoryId + ":" + workflowId + ":" + runId + ":" + attempt + ":" + locator);
            return new ProtectedEvidenceV2(input, new Binding(tenantId, accountId, installationId,
                    repositoryId, workflowId, runId, attempt, scopeRevision, pipelineId,
                    sourceUpdatedAt, occurredAt, commitSha, status, conclusion, service, environment));
        } catch (RuntimeException | CharacterCodingException invalid) {
            // Parser exceptions can contain protected values; never retain them as causes.
            throw new IllegalArgumentException("Invalid protected evidence envelope");
        }
    }

    private static JsonNode object(JsonNode node) {
        require(node != null && node.isObject());
        return node;
    }

    private static String text(JsonNode object, String field) {
        JsonNode node = object.get(field);
        require(node != null && node.isString());
        String value = node.asString();
        require(!value.isBlank());
        for (int i = 0; i < value.length(); i++) {
            char current = value.charAt(i);
            require(current != 0 && !Character.isLowSurrogate(current));
            if (Character.isHighSurrogate(current)) {
                require(++i < value.length() && Character.isLowSurrogate(value.charAt(i)));
            }
        }
        return value;
    }

    private static String nullableText(JsonNode object, String field, boolean required) {
        JsonNode node = object.get(field);
        require(node != null || !required);
        return node == null || node.isNull() ? null : text(object, field);
    }

    private static String safeId(JsonNode object, String field) {
        String value = text(object, field);
        EvidenceInput.requireSafeId(value, field);
        return value;
    }

    private static String externalId(JsonNode object, String field) {
        String value = text(object, field);
        require(value.matches("[1-9][0-9]*"));
        return value;
    }

    private static UUID uuid(JsonNode object, String field) {
        String value = text(object, field);
        UUID result = UUID.fromString(value);
        require(result.toString().equals(value) && !result.equals(new UUID(0, 0)));
        return result;
    }

    private static Instant timestamp(JsonNode object, String field) {
        OffsetDateTime value = OffsetDateTime.parse(text(object, field));
        require(value.getOffset().equals(ZoneOffset.UTC));
        return value.toInstant();
    }

    private static Long sequence(JsonNode evidence) {
        JsonNode node = evidence.get("sequence");
        if (node == null || node.isNull()) return null;
        require(node.isIntegralNumber() && node.canConvertToLong());
        long value = node.longValue();
        require(value >= 0);
        return value;
    }

    private static void require(boolean valid) {
        if (!valid) throw new IllegalArgumentException("Invalid protected evidence envelope");
    }

    @Override
    public String toString() {
        return "ProtectedEvidenceV2[protected]";
    }
}
