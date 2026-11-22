package org.pipesor.logevent.evidence.interfaces.rest;

import jakarta.servlet.http.HttpServletRequest;
import java.io.IOException;
import java.nio.ByteBuffer;
import java.nio.charset.CharacterCodingException;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.Collections;
import java.util.LinkedHashMap;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.RejectedExecutionException;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.TimeoutException;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.queryhandlers.CheckEvidenceMembershipHandler;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.http.CacheControl;
import org.springframework.http.ResponseEntity;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.web.bind.annotation.PostMapping;
import org.springframework.web.bind.annotation.RestController;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/**
 * Correlation evidence membership v1. Only the {@code correlation} workload with role
 * {@code Correlation.EvidenceMembership.Check} reaches this controller (route rule in the security
 * configuration). The lookup is scoped by the request's tenant, installation, revision, execution and
 * incident; the tenant must be this environment's tenant. Responses never reveal evidence content.
 */
@RestController
public final class EvidenceMembershipController implements AutoCloseable {
    public static final String PATH = "/internal/v1/evidence/membership-checks";
    public static final String CALLER = "correlation";
    public static final String ROLE = "Correlation.EvidenceMembership.Check";
    private static final Logger LOG = LoggerFactory.getLogger(EvidenceMembershipController.class);
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private static final Set<String> FIELDS = Set.of("requestId", "correlationId", "deadlineAt", "evidenceId",
            "executionId", "incidentId", "source", "tenantId", "githubInstallationId", "scopeRevision");

    /** Explicit limits; the tenant is the environment tenant ({@code PIPESOR_TENANT_ID}). */
    public record Settings(UUID tenant, Duration requestTimeout, int maxRequestBytes, int maxHeaderChars, int maxInFlight) {
        public Settings {
            if (tenant == null || tenant.equals(new UUID(0, 0)) || requestTimeout == null
                    || requestTimeout.isNegative() || requestTimeout.isZero() || maxRequestBytes < 1
                    || maxRequestBytes == Integer.MAX_VALUE || maxHeaderChars < 1 || maxInFlight < 1) {
                throw new IllegalArgumentException("Explicit membership settings are required");
            }
            requestTimeout.toNanos();
        }

        @Override public String toString() { return "EvidenceMembershipSettings[configured]"; }
    }

    private final Settings settings;
    private final CheckEvidenceMembershipHandler handler;
    private final Clock clock;
    private final Semaphore permits;
    private final ExecutorService work = Executors.newVirtualThreadPerTaskExecutor();

    public EvidenceMembershipController(EvidenceStore store, Settings settings, Clock clock) {
        this.settings = Objects.requireNonNull(settings);
        this.clock = Objects.requireNonNull(clock);
        this.permits = new Semaphore(settings.maxInFlight());
        UUID tenant = settings.tenant();
        this.handler = new CheckEvidenceMembershipHandler(store, (operation, query) ->
                operation == EvidenceAuthority.Operation.CHECK_MEMBERSHIP && query.scope() != null
                        && tenant.equals(query.scope().tenantId())
                        ? EvidenceAuthority.Decision.AUTHORIZED : EvidenceAuthority.Decision.DENIED);
    }

    @PostMapping(PATH)
    public ResponseEntity<byte[]> check(HttpServletRequest http, @AuthenticationPrincipal Jwt caller) {
        long started = System.nanoTime();
        String trace = null;
        try {
            if (http.getQueryString() != null || http.getHeader("Cookie") != null) throw new Rejected(400);
            String media = header(http, "Content-Type", true);
            if (!media.matches("(?i)application/json(?:\\s*;\\s*charset=utf-8)?")) throw new Rejected(415);
            String encoding = header(http, "Content-Encoding", false);
            if (encoding != null && !"identity".equalsIgnoreCase(encoding)) throw new Rejected(415);
            trace = header(http, "X-Correlation-Id", true);
            if (!trace.matches("[A-Za-z0-9._:-]{1,128}")) throw new Rejected(400);
            if (http.getContentLengthLong() > settings.maxRequestBytes()) throw new Rejected(413);
            byte[] bytes = http.getInputStream().readNBytes(settings.maxRequestBytes() + 1);
            if (bytes.length > settings.maxRequestBytes()) throw new Rejected(413);
            final Request request;
            try {
                request = parse(bytes, trace);
            } catch (Rejected rejected) {
                throw rejected;
            } catch (RuntimeException | CharacterCodingException invalid) {
                throw new Rejected(400);
            }
            if (!"github_actions".equals(request.query().source())) throw new Rejected(400);
            Instant expires = caller == null ? null : caller.getExpiresAt();
            if (expires == null) throw new Rejected(503);
            Instant deadline = request.deadline().isBefore(expires) ? request.deadline() : expires;
            long now = System.nanoTime();
            long remaining = Math.min(settings.requestTimeout().toNanos() - (now - started),
                    Duration.between(clock.instant(), deadline).toNanos());
            if (remaining <= 0) throw new Rejected(503);
            long endNanos = now + remaining;
            String decision = decide(request.query(), remaining);
            if (endNanos - System.nanoTime() <= 0 || !clock.instant().isBefore(deadline)) throw new Rejected(503);
            var body = new LinkedHashMap<String, Object>();
            body.put("requestId", request.id().toString());
            body.put("correlationId", trace);
            body.put("decision", decision);
            return respond(200, "application/json", body);
        } catch (Rejected rejected) {
            if (rejected.status == 503) LOG.warn("Membership check unavailable: deadline correlationId={}", trace);
            return failure(rejected.status);
        } catch (IOException | RuntimeException unavailable) {
            LOG.warn("Membership check unavailable: {} correlationId={}", unavailable.getClass().getSimpleName(), trace);
            return failure(503);
        }
    }

    private String decide(EvidenceMembershipQuery query, long remainingNanos) {
        if (!settings.tenant().equals(query.scope().tenantId())) return "DENIED";
        if (!permits.tryAcquire()) throw new Rejected(429);
        final Future<EvidenceStore.Membership> pending;
        try {
            pending = work.submit(() -> {
                try {
                    return handler.handleScoped(query);
                } finally {
                    permits.release();
                }
            });
        } catch (RejectedExecutionException closed) {
            permits.release();
            throw new Rejected(503);
        }
        try {
            return switch (pending.get(remainingNanos, TimeUnit.NANOSECONDS)) {
                case MATCH -> "AUTHORIZED";
                case NOT_READY -> "NOT_READY";
                case MISMATCH -> "MISMATCH";
            };
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            pending.cancel(true);
            throw new Rejected(503);
        } catch (TimeoutException late) {
            pending.cancel(true);
            throw new Rejected(503);
        } catch (ExecutionException failed) {
            LOG.warn("Membership lookup failed: {}", failed.getCause() == null ? "unknown"
                    : failed.getCause().getClass().getSimpleName());
            throw new Rejected(503);
        }
    }

    private String header(HttpServletRequest http, String name, boolean required) {
        var values = Collections.list(http.getHeaders(name));
        if (values.isEmpty()) {
            if (!required) return null;
            throw new Rejected(400);
        }
        if (values.size() != 1 || values.getFirst().isBlank() || values.getFirst().length() > settings.maxHeaderChars()) {
            throw new Rejected(400);
        }
        return values.getFirst();
    }

    private static Request parse(byte[] bytes, String trace) throws CharacterCodingException {
        String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        if (text.startsWith("﻿")) throw new Rejected(400);
        var json = JSON.readTree(text);
        if (json == null || !json.isObject() || !json.propertyNames().equals(FIELDS)
                || !trace.equals(text(json, "correlationId"))) throw new Rejected(400);
        var rawDeadline = text(json, "deadlineAt");
        if (!rawDeadline.endsWith("Z")) throw new Rejected(400);
        return new Request(uuid(json, "requestId"), Instant.parse(rawDeadline),
                new EvidenceMembershipQuery(uuid(json, "evidenceId"), uuid(json, "incidentId"),
                        uuid(json, "executionId"), text(json, "source"),
                        new EvidenceScope(uuid(json, "tenantId"), text(json, "githubInstallationId"), text(json, "scopeRevision"))));
    }

    private static UUID uuid(JsonNode json, String field) {
        String raw = text(json, field);
        var id = UUID.fromString(raw);
        if (!id.toString().equals(raw) || id.equals(new UUID(0, 0))) throw new Rejected(400);
        return id;
    }

    private static String text(JsonNode json, String field) {
        var node = json.get(field);
        if (node == null || !node.isString() || node.asString().isBlank()) throw new Rejected(400);
        return node.asString();
    }

    private static ResponseEntity<byte[]> failure(int status) {
        String title = switch (status) {
            case 400 -> "Bad Request"; case 413 -> "Content Too Large"; case 415 -> "Unsupported Media Type";
            case 429 -> "Too Many Requests"; default -> "Service Unavailable";
        };
        String code = switch (status) {
            case 400 -> "INVALID_REQUEST"; case 413 -> "REQUEST_TOO_LARGE"; case 415 -> "UNSUPPORTED_MEDIA_TYPE";
            case 429 -> "OVERLOADED"; default -> "UNAVAILABLE";
        };
        var body = new LinkedHashMap<String, Object>();
        body.put("type", "about:blank");
        body.put("title", title);
        body.put("status", status == 400 || status == 413 || status == 415 || status == 429 ? status : 503);
        body.put("code", code);
        return respond((int) body.get("status"), "application/problem+json", body);
    }

    private static ResponseEntity<byte[]> respond(int status, String contentType, Map<String, Object> body) {
        return ResponseEntity.status(status).cacheControl(CacheControl.noStore())
                .header("Content-Type", contentType).body(JSON.writeValueAsBytes(body));
    }

    private record Request(UUID id, Instant deadline, EvidenceMembershipQuery query) { }

    private static final class Rejected extends RuntimeException {
        final int status;

        Rejected(int status) {
            super(null, null, false, false);
            this.status = status;
        }
    }

    @Override public void close() { work.shutdownNow(); }
}
