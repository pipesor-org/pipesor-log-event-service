package org.pipesor.logevent.evidence.application.services;

import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;

/** Safe failure categories; never includes a requested ID or underlying provider cause. */
public final class EvidenceAccessException extends RuntimeException {
    private final EvidenceAuthority.Decision decision;

    private EvidenceAccessException(EvidenceAuthority.Decision decision) {
        super("Evidence authority: " + decision.name());
        this.decision = decision;
    }

    public EvidenceAuthority.Decision decision() {
        return decision;
    }

    public static void requireAuthorized(EvidenceAuthority authority, EvidenceAuthority.Operation operation,
                                         EvidenceMembershipQuery context) {
        EvidenceAuthority.Decision decision;
        try {
            decision = authority.check(operation, context);
        } catch (RuntimeException unavailable) {
            throw new EvidenceAccessException(EvidenceAuthority.Decision.UNAVAILABLE);
        }
        if (decision == null) decision = EvidenceAuthority.Decision.UNAVAILABLE;
        if (decision != EvidenceAuthority.Decision.AUTHORIZED) throw new EvidenceAccessException(decision);
    }
}
