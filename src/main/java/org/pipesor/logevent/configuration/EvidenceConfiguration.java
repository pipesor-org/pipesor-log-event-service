package org.pipesor.logevent.configuration;

import java.time.Clock;
import javax.sql.DataSource;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.ports.OperationalReferenceAuthority;
import org.pipesor.logevent.evidence.infrastructure.authority.HttpPipelineAuthority;
import org.pipesor.logevent.evidence.infrastructure.persistence.jdbc.JdbcEvidenceStore;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceIntake;
import org.pipesor.logevent.evidence.interfaces.rest.EvidenceMembershipController;
import org.pipesor.logevent.shared.security.PlatformAuthorities;
import org.pipesor.logevent.shared.security.PlatformSecurityConfiguration.PlatformRoutes;
import org.pipesor.logevent.shared.security.PlatformSecurityProperties;
import org.pipesor.logevent.shared.security.TransportPolicy;
import org.pipesor.logevent.shared.security.WorkloadTokens;
import org.springframework.boot.context.properties.EnableConfigurationProperties;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;
import org.springframework.http.HttpMethod;

/** Explicit composition of the evidence handlers, adapters and the service's route rules. */
@Configuration(proxyBeanMethods = false)
@EnableConfigurationProperties(LogEventProperties.class)
public class EvidenceConfiguration {

    @Bean
    Clock clock() {
        return Clock.systemUTC();
    }

    @Bean
    EvidenceStore evidenceStore(DataSource dataSource, Clock clock) {
        return new JdbcEvidenceStore(dataSource, clock);
    }

    @Bean
    OperationalReferenceAuthority pipelineAuthority(LogEventProperties settings, WorkloadTokens tokens,
            TransportPolicy transport, Clock clock) {
        var pipeline = settings.logEvent().pipeline();
        return new HttpPipelineAuthority(settings.endpoints().pipeline(),
                budget -> tokens.issue(HttpPipelineAuthority.TARGET, HttpPipelineAuthority.ROLE).value(),
                transport, clock, pipeline.timeout(), pipeline.maxResponseBytes());
    }

    @Bean
    ProtectedEvidenceIntake protectedEvidenceIntake(EvidenceStore store, OperationalReferenceAuthority authority,
            LogEventProperties settings) {
        return new ProtectedEvidenceIntake(store, authority, settings.logEvent().intake().maxMessageBytes());
    }

    @Bean
    EvidenceMembershipController.Settings membershipSettings(PlatformSecurityProperties platform, LogEventProperties settings) {
        var membership = settings.logEvent().membership();
        return new EvidenceMembershipController.Settings(platform.tenantId(), membership.requestTimeout(),
                membership.maxRequestBytes(), membership.maxHeaderChars(), membership.maxInFlight());
    }

    /** Route catalog (platform identity contract v1): correlation → log-event membership checks only. */
    @Bean
    PlatformRoutes platformRoutes() {
        return routes -> routes.requestMatchers(HttpMethod.POST, EvidenceMembershipController.PATH)
                .access(PlatformAuthorities.workload(EvidenceMembershipController.CALLER, EvidenceMembershipController.ROLE));
    }
}
