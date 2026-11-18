package org.pipesor.logevent.evidence.application.ports;

import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;

/** Internal persistence port. Callers use the authorized handlers, not this port as an API. */
public interface EvidenceStore {
    enum Registration { CREATED, UNCHANGED, CONFLICT }
    enum Membership { MATCH, NOT_READY, MISMATCH }

    Registration register(EvidenceInput input);

    /** Read only membership identifiers/source; do not load summary or excerpt. */
    Membership membership(EvidenceMembershipQuery query);
}
