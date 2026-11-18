package org.pipesor.logevent.evidence.application.queries;

import java.util.Objects;
import java.util.UUID;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;

public record EvidenceMembershipQuery(UUID evidenceId, UUID incidentId, UUID executionId, String source) {
    public EvidenceMembershipQuery {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(incidentId, "incidentId");
        Objects.requireNonNull(executionId, "executionId");
        EvidenceInput.requireSafeId(source, "source");
    }

    @Override
    public String toString() {
        return "EvidenceMembershipQuery[protected]";
    }
}
