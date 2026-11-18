package org.pipesor.logevent.evidence.application.services;

import java.util.Objects;
import java.util.UUID;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;

/** Authorized registration exposes only identity and delivery-independent persistence state. */
public record EvidenceRegistration(UUID evidenceId, EvidenceStore.Registration state) {
    public EvidenceRegistration {
        Objects.requireNonNull(evidenceId, "evidenceId");
        Objects.requireNonNull(state, "state");
    }
}
