package org.pipesor.logevent.configuration;

import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/**
 * Service Bus consumer settings. Exactly one of {@code connection-string} (local emulator only)
 * or {@code namespace} (managed identity through {@code DefaultAzureCredential}) is required.
 */
@ConfigurationProperties("pipesor.service-bus")
public record ServiceBusProperties(String connectionString, String namespace, String topic, String subscription,
        int concurrency, Duration lockRenewal, Duration drainTimeout) {
    public ServiceBusProperties {
        connectionString = blankToNull(connectionString);
        namespace = blankToNull(namespace);
    }

    private static String blankToNull(String value) {
        return value == null || value.isBlank() ? null : value.strip();
    }

    @Override public String toString() { return "ServiceBusProperties[" + topic + "/" + subscription + "]"; }
}
