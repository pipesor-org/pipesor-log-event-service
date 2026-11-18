package org.pipesor.logevent.evidence.application.queryhandlers;

import java.util.Objects;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.services.EvidenceAccessException;

public final class CheckEvidenceMembershipHandler {
    private final EvidenceStore store;
    private final EvidenceAuthority authority;

    public CheckEvidenceMembershipHandler(EvidenceStore store, EvidenceAuthority authority) {
        this.store = Objects.requireNonNull(store, "store");
        this.authority = Objects.requireNonNull(authority, "authority");
    }

    /** Scoped read for the Correlation membership exchange; never downgrades to a legacy lookup. */
    public EvidenceStore.Membership handleScoped(EvidenceMembershipQuery query) {
        Objects.requireNonNull(query, "query");
        Objects.requireNonNull(query.scope(), "Frozen evidence scope is required");
        return handle(query);
    }

    public EvidenceStore.Membership handle(EvidenceMembershipQuery query) {
        Objects.requireNonNull(query, "query");
        EvidenceAccessException.requireAuthorized(authority, EvidenceAuthority.Operation.CHECK_MEMBERSHIP, query);
        var membership = store.membership(query);
        if (membership == null) throw new EvidenceStoreUnavailableException();
        return membership;
    }
}
