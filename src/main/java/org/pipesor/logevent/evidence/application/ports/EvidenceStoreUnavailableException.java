package org.pipesor.logevent.evidence.application.ports;

/** Fixed error deliberately omits driver details, connection settings and evidence. */
public final class EvidenceStoreUnavailableException extends RuntimeException {
    public EvidenceStoreUnavailableException() {
        super("Evidence store unavailable");
    }
}
