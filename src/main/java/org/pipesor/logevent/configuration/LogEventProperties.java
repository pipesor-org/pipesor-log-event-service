package org.pipesor.logevent.configuration;

import java.net.URI;
import java.time.Duration;
import org.springframework.boot.context.properties.ConfigurationProperties;

/** Service limits and outbound endpoints (runtime manifest: {@code PIPESOR_ENDPOINTS_PIPELINE}). */
@ConfigurationProperties("pipesor")
public record LogEventProperties(Endpoints endpoints, LogEvent logEvent) {
    public record Endpoints(URI pipeline) { }

    public record LogEvent(Intake intake, Pipeline pipeline, Membership membership) { }

    public record Intake(int maxMessageBytes) { }

    public record Pipeline(Duration timeout, int maxResponseBytes) { }

    public record Membership(Duration requestTimeout, int maxRequestBytes, int maxHeaderChars, int maxInFlight) { }

    public LogEventProperties {
        if (endpoints == null || endpoints.pipeline() == null) {
            throw new IllegalArgumentException("pipesor.endpoints.pipeline is required");
        }
        if (logEvent == null || logEvent.intake() == null || logEvent.pipeline() == null || logEvent.membership() == null) {
            throw new IllegalArgumentException("pipesor.log-event limits are required");
        }
    }
}
