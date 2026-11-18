package org.pipesor.logevent.evidence;

import static org.junit.jupiter.api.Assertions.*;

import java.util.concurrent.atomic.AtomicInteger;
import java.util.concurrent.atomic.AtomicReference;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.EnumSource;
import org.pipesor.logevent.evidence.application.commandhandlers.RegisterEvidenceHandler;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.queryhandlers.CheckEvidenceMembershipHandler;
import org.pipesor.logevent.evidence.application.services.EvidenceAccessException;

class EvidenceAuthorizationTest {
    private final EvidenceInput input = EvidenceInputTest.input("Failure [redacted]", null, null, null);
    private final EvidenceMembershipQuery query = new EvidenceMembershipQuery(
            input.evidenceId(), input.incidentId(), input.executionId(), input.source());

    @ParameterizedTest
    @EnumSource(value = EvidenceAuthority.Decision.class, names = "AUTHORIZED", mode = EnumSource.Mode.EXCLUDE)
    void refusesBothOperationsBeforeAnyDatabaseAccess(EvidenceAuthority.Decision decision) {
        var calls = new AtomicInteger();
        var store = countingStore(calls);
        var register = new RegisterEvidenceHandler(store, (operation, ignored) -> decision);
        var lookup = new CheckEvidenceMembershipHandler(store, (operation, ignored) -> decision);
        assertEquals(decision, assertThrows(EvidenceAccessException.class, () -> register.handle(input)).decision());
        assertEquals(decision, assertThrows(EvidenceAccessException.class, () -> lookup.handle(query)).decision());
        assertEquals(0, calls.get());
    }

    @Test
    void missingAuthorityDecisionAndProviderErrorsFailClosedWithoutProviderDetails() {
        var calls = new AtomicInteger();
        var store = countingStore(calls);
        assertEquals(EvidenceAuthority.Decision.UNAVAILABLE, assertThrows(EvidenceAccessException.class,
                () -> new RegisterEvidenceHandler(store, (operation, ignored) -> null).handle(input)).decision());
        var error = assertThrows(EvidenceAccessException.class, () -> new CheckEvidenceMembershipHandler(
                store, (operation, ignored) -> { throw new IllegalStateException("private-provider-detail"); }).handle(query));
        assertEquals(EvidenceAuthority.Decision.UNAVAILABLE, error.decision());
        assertFalse(error.toString().contains("private-provider-detail"));
        assertNull(error.getCause());
        assertEquals(0, calls.get());
    }

    @Test
    void requiresInjectedAuthorityRatherThanDefaultingToAllowAll() {
        var store = countingStore(new AtomicInteger());
        assertThrows(NullPointerException.class, () -> new RegisterEvidenceHandler(store, null));
        assertThrows(NullPointerException.class, () -> new CheckEvidenceMembershipHandler(store, null));
    }

    @Test
    void checksExactEvidenceIdentityAndContextBeforeReturningMinimalResults() {
        var calls = new AtomicInteger();
        var checked = new AtomicReference<EvidenceMembershipQuery>();
        EvidenceAuthority authority = (operation, context) -> {
            assertEquals(EvidenceAuthority.Operation.REGISTER, operation);
            assertEquals(0, calls.get());
            checked.set(context);
            return EvidenceAuthority.Decision.AUTHORIZED;
        };
        var result = new RegisterEvidenceHandler(countingStore(calls), authority).handle(input);
        assertEquals(query, checked.get());
        assertEquals(input.evidenceId(), result.evidenceId());
        assertEquals(EvidenceStore.Registration.CREATED, result.state());
        assertFalse(result.toString().contains(input.summary()));
        assertEquals(1, calls.get());
    }

    @Test
    void successfulQueryReturnsMembershipOnlyAfterAuthorization() {
        var calls = new AtomicInteger();
        var handler = new CheckEvidenceMembershipHandler(countingStore(calls), (operation, context) -> {
            assertEquals(EvidenceAuthority.Operation.CHECK_MEMBERSHIP, operation);
            assertEquals(query, context);
            assertEquals(0, calls.get());
            return EvidenceAuthority.Decision.AUTHORIZED;
        });
        assertEquals(EvidenceStore.Membership.MATCH, handler.handle(query));
        assertEquals(1, calls.get());
    }

    private static EvidenceStore countingStore(AtomicInteger calls) {
        return new EvidenceStore() {
            public Registration register(EvidenceInput input) {
                calls.incrementAndGet();
                return Registration.CREATED;
            }

            public Membership membership(EvidenceMembershipQuery query) {
                calls.incrementAndGet();
                return Membership.MATCH;
            }
        };
    }
}
