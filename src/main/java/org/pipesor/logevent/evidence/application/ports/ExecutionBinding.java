package org.pipesor.logevent.evidence.application.ports;

import java.time.Instant;
import java.util.UUID;

/** Full historical binding of a protected event for the source authority; identities alone do not grant access. */
public record ExecutionBinding(
        UUID tenantId, String githubAccountId, String githubInstallationId,
        String githubRepositoryId, String githubWorkflowId, String githubRunId,
        int runAttempt, String scopeRevision, UUID pipelineId,
        Instant sourceUpdatedAt, Instant occurredAt, String commitSha,
        String status, String conclusion, String service, String environment) {
    @Override
    public String toString() {
        return "ExecutionBinding[protected]";
    }
}
