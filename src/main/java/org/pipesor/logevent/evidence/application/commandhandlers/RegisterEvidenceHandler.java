package org.pipesor.logevent.evidence.application.commandhandlers;

import java.util.Objects;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.services.EvidenceAccessException;
import org.pipesor.logevent.evidence.application.services.EvidenceRegistration;

public final class RegisterEvidenceHandler {
    private final EvidenceStore store;
    private final EvidenceAuthority authority;

    public RegisterEvidenceHandler(EvidenceStore store, EvidenceAuthority authority) {
        this.store = Objects.requireNonNull(store, "store");
        this.authority = Objects.requireNonNull(authority, "authority");
    }

    public EvidenceRegistration handle(EvidenceInput input) {
        Objects.requireNonNull(input, "input");
        EvidenceAccessException.requireAuthorized(authority, EvidenceAuthority.Operation.REGISTER,
                new EvidenceMembershipQuery(
                input.evidenceId(), input.incidentId(), input.executionId(), input.source()));
        var state = store.register(input);
        if (state == null) throw new EvidenceStoreUnavailableException();
        return new EvidenceRegistration(input.evidenceId(), state);
    }
}
