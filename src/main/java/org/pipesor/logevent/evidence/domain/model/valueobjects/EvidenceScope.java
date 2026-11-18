package org.pipesor.logevent.evidence.domain.model.valueobjects;

import java.util.UUID;

/** Immutable registration provenance. Current access requires a separate authority check. */
public record EvidenceScope(UUID tenantId, String installationId, String revision) {
    public EvidenceScope {
        if (tenantId == null || tenantId.equals(new UUID(0, 0))
                || installationId == null || !installationId.matches("[1-9][0-9]*")
                || revision == null || !revision.matches("[A-Za-z0-9._:-]{1,128}")) {
            throw new IllegalArgumentException("Invalid evidence scope");
        }
    }

    @Override public String toString() { return "EvidenceScope[protected]"; }
}
