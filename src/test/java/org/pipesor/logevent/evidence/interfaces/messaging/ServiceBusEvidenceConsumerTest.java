package org.pipesor.logevent.evidence.interfaces.messaging;

import java.util.ArrayList;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import org.junit.jupiter.api.Test;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.services.EvidenceAccessException;
import org.pipesor.logevent.evidence.application.services.EvidenceRegistration;
import org.pipesor.logevent.evidence.interfaces.messaging.ServiceBusEvidenceConsumer.Outcome;

import static org.assertj.core.api.Assertions.assertThat;

class ServiceBusEvidenceConsumerTest {
    private static final UUID EVIDENCE = UUID.fromString("e6988490-6322-590d-b48d-662b154b55d9");

    @Test
    void completesRegisteredAndDuplicateEvidenceAndPassesBrokerMetadata() {
        var seen = new ArrayList<String>();
        var consumer = new ServiceBusEvidenceConsumer((body, messageId, correlationId, eventType, schemaMajor) -> {
            seen.add(new String(body) + "|" + messageId + "|" + correlationId + "|" + eventType + "|" + schemaMajor);
            return new EvidenceRegistration(EVIDENCE, EvidenceStore.Registration.CREATED);
        });
        var delivery = new FakeDelivery(2);
        assertThat(consumer.accept(delivery)).isEqualTo(Outcome.REGISTERED);
        assertThat(delivery.settlements).containsExactly("complete");
        assertThat(seen).containsExactly("{}|message-1|trace-1|protected_workflow_evidence|2");

        var duplicate = new FakeDelivery(2);
        assertThat(new ServiceBusEvidenceConsumer(registration(EvidenceStore.Registration.UNCHANGED)).accept(duplicate))
                .isEqualTo(Outcome.DUPLICATE);
        assertThat(duplicate.settlements).containsExactly("complete");
    }

    @Test
    void abandonsWhileTheOwnerIsNotReadyOrUnavailable() {
        for (var decision : List.of(EvidenceAuthority.Decision.NOT_READY, EvidenceAuthority.Decision.UNAVAILABLE)) {
            var delivery = new FakeDelivery(2);
            assertThat(new ServiceBusEvidenceConsumer(refused(decision)).accept(delivery)).isEqualTo(Outcome.RETRY);
            assertThat(delivery.settlements).containsExactly("abandon");
        }
        var storeDown = new FakeDelivery(2);
        assertThat(new ServiceBusEvidenceConsumer((b, m, c, e, s) -> { throw new EvidenceStoreUnavailableException(); })
                .accept(storeDown)).isEqualTo(Outcome.RETRY);
        assertThat(storeDown.settlements).containsExactly("abandon");
        var unexpected = new FakeDelivery(2);
        assertThat(new ServiceBusEvidenceConsumer((b, m, c, e, s) -> { throw new IllegalStateException("secret"); })
                .accept(unexpected)).isEqualTo(Outcome.RETRY);
        assertThat(unexpected.settlements).containsExactly("abandon");
    }

    @Test
    void deadLettersPermanentContractFailuresWithAFixedReason() {
        var invalid = new FakeDelivery(2);
        assertThat(new ServiceBusEvidenceConsumer((b, m, c, e, s) -> { throw new IllegalArgumentException("payload"); })
                .accept(invalid)).isEqualTo(Outcome.DEAD_LETTERED);
        assertThat(invalid.settlements).containsExactly("deadLetter:INVALID_PROTECTED_EVIDENCE");

        var conflict = new FakeDelivery(2);
        new ServiceBusEvidenceConsumer(registration(EvidenceStore.Registration.CONFLICT)).accept(conflict);
        assertThat(conflict.settlements).containsExactly("deadLetter:EVIDENCE_CONFLICT");

        var denied = new FakeDelivery(2);
        new ServiceBusEvidenceConsumer(refused(EvidenceAuthority.Decision.DENIED)).accept(denied);
        assertThat(denied.settlements).containsExactly("deadLetter:EVIDENCE_DENIED");

        var mismatch = new FakeDelivery(2);
        new ServiceBusEvidenceConsumer(refused(EvidenceAuthority.Decision.MISMATCH)).accept(mismatch);
        assertThat(mismatch.settlements).containsExactly("deadLetter:REFERENCE_MISMATCH");

        for (var properties : List.<Map<String, Object>>of(Map.of("eventType", "execution.snapshot", "schemaMajor", 2),
                Map.of("eventType", "protected_workflow_evidence", "schemaMajor", 1),
                Map.of("eventType", "protected_workflow_evidence"))) {
            var unsupported = new FakeDelivery(properties);
            new ServiceBusEvidenceConsumer((b, m, c, e, s) -> { throw new AssertionError("must not decode"); }).accept(unsupported);
            assertThat(unsupported.settlements).containsExactly("deadLetter:UNSUPPORTED_EVENT");
        }
    }

    @Test
    void lostSettlementIsLoggedAndLeftToRedelivery() {
        var delivery = new FakeDelivery(2) {
            @Override public void complete() { throw new IllegalStateException("lock lost"); }
        };
        assertThat(new ServiceBusEvidenceConsumer(registration(EvidenceStore.Registration.CREATED)).accept(delivery))
                .isEqualTo(Outcome.REGISTERED);
    }

    private static ServiceBusEvidenceConsumer.Receiver registration(EvidenceStore.Registration state) {
        return (b, m, c, e, s) -> new EvidenceRegistration(EVIDENCE, state);
    }

    private static ServiceBusEvidenceConsumer.Receiver refused(EvidenceAuthority.Decision decision) {
        return (b, m, c, e, s) -> {
            EvidenceAccessException.requireAuthorized((operation, query) -> decision, EvidenceAuthority.Operation.REGISTER,
                    new EvidenceMembershipQuery(EVIDENCE, UUID.randomUUID(), UUID.randomUUID(), "github_actions"));
            throw new AssertionError("unreachable");
        };
    }

    private static class FakeDelivery implements ServiceBusEvidenceConsumer.Delivery {
        final List<String> settlements = new ArrayList<>();
        final Map<String, Object> properties;

        FakeDelivery(int schemaMajor) { this(Map.of("eventType", "protected_workflow_evidence", "schemaMajor", schemaMajor)); }

        FakeDelivery(Map<String, Object> properties) { this.properties = properties; }

        @Override public byte[] body() { return "{}".getBytes(); }
        @Override public String messageId() { return "message-1"; }
        @Override public String correlationId() { return "trace-1"; }
        @Override public Object property(String name) { return properties.get(name); }
        @Override public long deliveryCount() { return 1; }
        @Override public void complete() { settlements.add("complete"); }
        @Override public void abandon() { settlements.add("abandon"); }
        @Override public void deadLetter(String reason) { settlements.add("deadLetter:" + reason); }
    }
}
