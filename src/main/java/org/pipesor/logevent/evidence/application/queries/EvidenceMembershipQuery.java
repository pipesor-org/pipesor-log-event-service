package org.pipesor.logevent.evidence.application.queries;

import java.util.Objects;
import java.util.UUID;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;

public record EvidenceMembershipQuery(UUID evidenceId, UUID incidentId, UUID executionId, String source, EvidenceScope scope) {
    public EvidenceMembershipQuery(UUID evidenceId, UUID incidentId, UUID executionId, String source) {
        this(evidenceId, incidentId, executionId, source, null);
    }

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
