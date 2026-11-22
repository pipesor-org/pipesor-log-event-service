package org.pipesor.logevent.evidence.interfaces.messaging;

import com.azure.messaging.servicebus.ServiceBusReceivedMessageContext;
import com.azure.messaging.servicebus.models.DeadLetterOptions;
import java.util.Objects;
import org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException;
import org.pipesor.logevent.evidence.application.services.EvidenceAccessException;
import org.pipesor.logevent.evidence.application.services.EvidenceRegistration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Settles {@code protected_workflow_evidence} deliveries of subscription {@code log-event}.
 * Registered or duplicate evidence completes; a not-ready or unavailable owner check is abandoned
 * for redelivery (Pipeline may not have applied the snapshot yet; the broker's max delivery count
 * bounds retries); permanent contract failures are dead-lettered with a fixed reason. Payloads,
 * excerpts and exception messages are never logged.
 */
public final class ServiceBusEvidenceConsumer {
    public static final String EVENT_TYPE = "protected_workflow_evidence";
    private static final Logger LOG = LoggerFactory.getLogger(ServiceBusEvidenceConsumer.class);

    @FunctionalInterface
    public interface Receiver {
        EvidenceRegistration receive(byte[] body, String messageId, String correlationId, String eventType, int schemaMajor);
    }

    /** Broker-neutral view of one locked delivery. */
    public interface Delivery {
        byte[] body();
        String messageId();
        String correlationId();
        Object property(String name);
        long deliveryCount();
        void complete();
        void abandon();
        void deadLetter(String reason);
    }

    public enum Outcome { REGISTERED, DUPLICATE, RETRY, DEAD_LETTERED }

    private final Receiver receiver;

    public ServiceBusEvidenceConsumer(Receiver receiver) {
        this.receiver = Objects.requireNonNull(receiver);
    }

    public void accept(ServiceBusReceivedMessageContext context) {
        accept(new Delivery() {
            @Override public byte[] body() { return context.getMessage().getBody().toBytes(); }
            @Override public String messageId() { return context.getMessage().getMessageId(); }
            @Override public String correlationId() { return context.getMessage().getCorrelationId(); }
            @Override public Object property(String name) { return context.getMessage().getApplicationProperties().get(name); }
            @Override public long deliveryCount() { return context.getMessage().getDeliveryCount(); }
            @Override public void complete() { context.complete(); }
            @Override public void abandon() { context.abandon(); }
            @Override public void deadLetter(String reason) {
                context.deadLetter(new DeadLetterOptions().setDeadLetterReason(reason));
            }
        });
    }

    public Outcome accept(Delivery delivery) {
        String messageId = safe(delivery.messageId());
        String correlationId = safe(delivery.correlationId());
        Object eventType = delivery.property("eventType");
        Integer schemaMajor = schemaMajor(delivery.property("schemaMajor"));
        if (!EVENT_TYPE.equals(eventType) || schemaMajor == null || schemaMajor != 2) {
            return deadLetter(delivery, "UNSUPPORTED_EVENT", messageId, correlationId);
        }
        final EvidenceRegistration registration;
        try {
            registration = receiver.receive(delivery.body(), delivery.messageId(), delivery.correlationId(),
                    EVENT_TYPE, schemaMajor);
        } catch (IllegalArgumentException invalid) {
            return deadLetter(delivery, "INVALID_PROTECTED_EVIDENCE", messageId, correlationId);
        } catch (EvidenceAccessException refused) {
            return switch (refused.decision()) {
                case NOT_READY, UNAVAILABLE -> retry(delivery, "AUTHORITY_" + refused.decision().name(), messageId, correlationId);
                case DENIED -> deadLetter(delivery, "EVIDENCE_DENIED", messageId, correlationId);
                case MISMATCH -> deadLetter(delivery, "REFERENCE_MISMATCH", messageId, correlationId);
                case AUTHORIZED -> retry(delivery, "AUTHORITY_INCONSISTENT", messageId, correlationId);
            };
        } catch (EvidenceStoreUnavailableException unavailable) {
            return retry(delivery, "STORE_UNAVAILABLE", messageId, correlationId);
        } catch (RuntimeException unexpected) {
            LOG.error("Evidence intake failed: {} messageId={} correlationId={}",
                    unexpected.getClass().getSimpleName(), messageId, correlationId);
            return retry(delivery, "INTAKE_FAILED", messageId, correlationId);
        }
        return switch (registration.state()) {
            case CREATED -> complete(delivery, Outcome.REGISTERED, messageId, correlationId);
            case UNCHANGED -> complete(delivery, Outcome.DUPLICATE, messageId, correlationId);
            case CONFLICT -> deadLetter(delivery, "EVIDENCE_CONFLICT", messageId, correlationId);
        };
    }

    private static Outcome complete(Delivery delivery, Outcome outcome, String messageId, String correlationId) {
        // Settlement is outside the store transaction: a lost acknowledgement is redelivered and replays as a duplicate.
        settle(delivery::complete, messageId, correlationId);
        LOG.info("Evidence {} messageId={} correlationId={}", outcome == Outcome.REGISTERED ? "registered" : "duplicate",
                messageId, correlationId);
        return outcome;
    }

    private static Outcome retry(Delivery delivery, String reason, String messageId, String correlationId) {
        settle(delivery::abandon, messageId, correlationId);
        LOG.warn("Evidence delivery abandoned for redelivery: reason={} deliveryCount={} messageId={} correlationId={}",
                reason, delivery.deliveryCount(), messageId, correlationId);
        return Outcome.RETRY;
    }

    private static Outcome deadLetter(Delivery delivery, String reason, String messageId, String correlationId) {
        settle(() -> delivery.deadLetter(reason), messageId, correlationId);
        LOG.warn("Evidence delivery dead-lettered: reason={} messageId={} correlationId={}", reason, messageId, correlationId);
        return Outcome.DEAD_LETTERED;
    }

    private static void settle(Runnable settlement, String messageId, String correlationId) {
        try {
            settlement.run();
        } catch (RuntimeException lost) {
            // The lock expires and the broker redelivers; registration is idempotent.
            LOG.warn("Evidence settlement failed: {} messageId={} correlationId={}",
                    lost.getClass().getSimpleName(), messageId, correlationId);
        }
    }

    private static Integer schemaMajor(Object value) {
        if (value instanceof Integer || value instanceof Long || value instanceof Short || value instanceof Byte) {
            long major = ((Number) value).longValue();
            return major >= 0 && major <= Integer.MAX_VALUE ? (int) major : null;
        }
        if (value instanceof String text && text.matches("[0-9]{1,9}")) return Integer.parseInt(text);
        return null;
    }

    /** Broker identifiers are logged only when they have the safe identifier shape. */
    private static String safe(String value) {
        return value != null && value.matches("[A-Za-z0-9._:-]{1,128}") ? value : "invalid";
    }
}
