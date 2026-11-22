package org.pipesor.logevent.configuration;

import com.azure.identity.DefaultAzureCredentialBuilder;
import com.azure.messaging.servicebus.ServiceBusClientBuilder;
import com.azure.messaging.servicebus.ServiceBusErrorContext;
import com.azure.messaging.servicebus.ServiceBusProcessorClient;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceIntake;
import org.pipesor.logevent.evidence.interfaces.messaging.ServiceBusEvidenceConsumer;
import org.pipesor.logevent.shared.security.TransportPolicy;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.boot.autoconfigure.condition.ConditionalOnBooleanProperty;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.boot.health.contributor.Health;
import org.springframework.boot.health.contributor.HealthIndicator;
import org.springframework.context.SmartLifecycle;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

/**
 * Subscription {@code log-event} on topic {@code workflow-evidence}. The credential is selected by
 * configuration: an emulator connection string (local profile only) or the namespace with
 * {@code DefaultAzureCredential} (managed identity in Azure).
 */
@Configuration(proxyBeanMethods = false)
@ConditionalOnBooleanProperty(name = "pipesor.service-bus.enabled", matchIfMissing = true)
@EnableConfigurationProperties(ServiceBusProperties.class)
public class ServiceBusConfiguration {
    private static final Logger LOG = LoggerFactory.getLogger(ServiceBusConfiguration.class);

    @Bean
    EvidenceReceiver evidenceReceiver(ServiceBusProperties settings, ProtectedEvidenceIntake intake, TransportPolicy transport) {
        if (settings.topic() == null || settings.topic().isBlank() || settings.subscription() == null
                || settings.subscription().isBlank() || settings.concurrency() < 1 || settings.lockRenewal() == null
                || settings.lockRenewal().isNegative() || settings.drainTimeout() == null
                || settings.drainTimeout().isNegative() || settings.drainTimeout().isZero()) {
            throw new IllegalArgumentException("Complete Service Bus topic/subscription and valid delivery limits are required");
        }
        if ((settings.connectionString() == null) == (settings.namespace() == null)) {
            throw new IllegalArgumentException("Exactly one of PIPESOR_SERVICE_BUS_CONNECTION_STRING or PIPESOR_SERVICE_BUS_NAMESPACE is required");
        }
        var builder = new ServiceBusClientBuilder();
        if (settings.connectionString() != null) {
            if (!transport.loopbackHttpAllowed()) {
                throw new IllegalStateException("A Service Bus connection string is allowed only under the local profile");
            }
            builder.connectionString(settings.connectionString());
        } else {
            builder.credential(settings.namespace(), new DefaultAzureCredentialBuilder().build());
        }
        var consumer = new ServiceBusEvidenceConsumer(intake::receive);
        var processor = builder.processor()
                .topicName(settings.topic()).subscriptionName(settings.subscription())
                .disableAutoComplete().prefetchCount(0).maxConcurrentCalls(settings.concurrency())
                .maxAutoLockRenewDuration(settings.lockRenewal())
                .drainTimeout(settings.drainTimeout())
                .processMessage(consumer::accept)
                .processError(ServiceBusConfiguration::receiveFailure)
                .buildProcessorClient();
        return new EvidenceReceiver(processor);
    }

    @Bean
    HealthIndicator serviceBusHealthIndicator(EvidenceReceiver receiver) {
        return () -> receiver.isProcessing() ? Health.up().build() : Health.down().build();
    }

    private static void receiveFailure(ServiceBusErrorContext error) {
        LOG.warn("Service Bus receive failure: source={} {}", error.getErrorSource(),
                error.getException() == null ? "unknown" : error.getException().getClass().getSimpleName());
    }

    /** Starts the processor with the application context and drains it on shutdown. */
    public static final class EvidenceReceiver implements SmartLifecycle {
        private final ServiceBusProcessorClient client;
        private volatile boolean running;

        EvidenceReceiver(ServiceBusProcessorClient client) { this.client = client; }

        @Override public void start() {
            client.start();
            running = true;
        }

        @Override public void stop() {
            running = false;
            client.close();
        }

        @Override public boolean isRunning() { return running; }

        boolean isProcessing() { return running && client.isRunning(); }
    }
}
