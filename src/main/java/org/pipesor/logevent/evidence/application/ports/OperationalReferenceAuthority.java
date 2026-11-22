package org.pipesor.logevent.evidence.application.ports;

import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;

/**
 * Source authority for protected evidence registration: confirms the historical execution
 * binding and the logical incident/execution references with the owner (Pipeline).
 * Implementations must fail closed and return {@link EvidenceAuthority.Decision#UNAVAILABLE}
 * when they cannot establish a decision.
 */
@FunctionalInterface
public interface OperationalReferenceAuthority {
    EvidenceAuthority.Decision verify(ExecutionBinding binding, EvidenceMembershipQuery references, String correlationId);
}
