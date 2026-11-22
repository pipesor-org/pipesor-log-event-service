package org.pipesor.logevent.evidence.interfaces.messaging;

import java.util.Objects;
import org.pipesor.logevent.evidence.application.commandhandlers.RegisterEvidenceHandler;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.ports.OperationalReferenceAuthority;
import org.pipesor.logevent.evidence.application.services.EvidenceRegistration;

/** Protected evidence intake. The authority must be bound to the authenticated delivery channel. */
public final class ProtectedEvidenceIntake {
    private final EvidenceStore store;
    private final OperationalReferenceAuthority authority;
    private final int maxBytes;

    public ProtectedEvidenceIntake(EvidenceStore store, OperationalReferenceAuthority authority, int maxBytes) {
        this.store = Objects.requireNonNull(store);
        this.authority = Objects.requireNonNull(authority);
        if (maxBytes < 1) throw new IllegalArgumentException("An explicit positive event byte limit is required");
        this.maxBytes = maxBytes;
    }

    /**
     * Decodes and registers one protected event.
     *
     * @throws IllegalArgumentException for an invalid envelope (permanent)
     * @throws org.pipesor.logevent.evidence.application.services.EvidenceAccessException when the authority does not authorize
     * @throws org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException when persistence is unavailable
     */
    public EvidenceRegistration receive(byte[] body, String messageId, String correlationId, String eventType, int schemaMajor) {
        var event = ProtectedEvidenceV2.decode(body, maxBytes, messageId, correlationId, eventType, schemaMajor);
        return new RegisterEvidenceHandler(store, (operation, references) ->
                authority.verify(event.binding(), references, event.input().correlationId()))
                .handle(event.input());
    }
}
