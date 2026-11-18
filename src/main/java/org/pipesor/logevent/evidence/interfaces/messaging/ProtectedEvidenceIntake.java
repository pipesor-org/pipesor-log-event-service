package org.pipesor.logevent.evidence.interfaces.messaging;

import java.util.Objects;
import org.pipesor.logevent.evidence.application.commandhandlers.RegisterEvidenceHandler;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.services.EvidenceRegistration;

/** Explicit local composition. The authority must be bound to the authenticated delivery channel. */
public final class ProtectedEvidenceIntake {
    @FunctionalInterface
    public interface Authority {
        EvidenceAuthority.Decision verify(ProtectedEvidenceV2.Binding binding, EvidenceMembershipQuery references,
                String correlationId);
    }

    private final EvidenceStore store;
    private final Authority authority;
    private final int maxBytes;

    public ProtectedEvidenceIntake(EvidenceStore store, Authority authority, int maxBytes) {
        this.store = Objects.requireNonNull(store);
        this.authority = Objects.requireNonNull(authority);
        if (maxBytes < 1) throw new IllegalArgumentException("An explicit positive event byte limit is required");
        this.maxBytes = maxBytes;
    }

    public EvidenceRegistration receive(byte[] body, String messageId, String correlationId, String eventType, int schemaMajor) {
        var event = ProtectedEvidenceV2.decode(body, maxBytes, messageId, correlationId, eventType, schemaMajor);
        return new RegisterEvidenceHandler(store, (operation, references) -> authority.verify(event.binding(), references, event.input().correlationId()))
                .handle(event.input());
    }
}
