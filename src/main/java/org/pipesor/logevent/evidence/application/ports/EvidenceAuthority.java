package org.pipesor.logevent.evidence.application.ports;

import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;

/**
 * A required boundary adapter must authorize the current trusted caller for the
 * exact evidence ID and the requested context, and verify the committed
 * incident/execution binding. Authorizing only the claimed incident/execution
 * would leak the existence of evidence from another scope through MISMATCH.
 * For registration the evidence ID is prospective. IDs alone never establish access.
 * An adapter unable to establish this authority must fail closed.
 * There is intentionally no permissive production implementation.
 */
@FunctionalInterface
public interface EvidenceAuthority {
    enum Operation { REGISTER, CHECK_MEMBERSHIP }
    enum Decision { AUTHORIZED, DENIED, NOT_READY, UNAVAILABLE, MISMATCH }

    Decision check(Operation operation, EvidenceMembershipQuery context);
}
