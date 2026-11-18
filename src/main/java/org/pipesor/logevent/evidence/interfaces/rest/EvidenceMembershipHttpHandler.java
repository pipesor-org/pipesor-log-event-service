package org.pipesor.logevent.evidence.interfaces.rest;

import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpHandler;
import java.io.IOException;
import java.net.URI;
import java.nio.ByteBuffer;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.Set;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Semaphore;
import java.util.concurrent.TimeUnit;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.queryhandlers.CheckEvidenceMembershipHandler;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.springframework.security.oauth2.jwt.Jwt;
import org.springframework.security.oauth2.jwt.JwtDecoder;
import org.springframework.security.oauth2.jwt.NimbusJwtDecoder;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Explicit internal composition. Correlation is delegated the exact-scope Pipeline preflight. */
public final class EvidenceMembershipHttpHandler implements HttpHandler, AutoCloseable {
    public static final String PATH = "/internal/v1/evidence/membership-checks";
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS).build();
    private static final Set<String> FIELDS = Set.of("requestId", "correlationId", "deadlineAt", "evidenceId",
            "executionId", "incidentId", "source", "tenantId", "githubInstallationId", "scopeRevision");

    public record Settings(URI issuer, URI jwkSetUri, String audience, UUID directoryTenant,
            UUID callerClient, UUID callerPrincipal, String role, UUID captureTenant, String installationId,
            Duration clockSkew, Duration requestTimeout, int maxRequestBytes, int maxHeaderChars, int maxInFlight) {
        public Settings {
            if (!https(issuer) || !https(jwkSetUri) || audience == null || audience.isBlank()
                    || !id(directoryTenant) || !id(callerClient) || !id(callerPrincipal) || !id(captureTenant)
                    || role == null || role.isBlank() || installationId == null || !installationId.matches("[1-9][0-9]*")
                    || clockSkew == null || clockSkew.isNegative() || requestTimeout == null
                    || requestTimeout.isNegative() || requestTimeout.isZero() || maxRequestBytes < 1
                    || maxRequestBytes == Integer.MAX_VALUE || maxHeaderChars < 1 || maxInFlight < 1) {
                throw new IllegalArgumentException("Explicit membership settings are required");
            }
            requestTimeout.toNanos();
        }
        @Override public String toString() { return "EvidenceMembershipSettings[configured]"; }
    }

    private final Settings settings;
    private final JwtDecoder tokens;
    private final EvidenceStore store;
    private final Clock clock;
    private final Semaphore permits;
    private final ExecutorService work = Executors.newVirtualThreadPerTaskExecutor();

    public EvidenceMembershipHttpHandler(EvidenceStore store, Settings settings) {
        this(store, settings, NimbusJwtDecoder.withJwkSetUri(settings.jwkSetUri().toString()).build(), Clock.systemUTC());
    }

    public EvidenceMembershipHttpHandler(EvidenceStore store, Settings settings, JwtDecoder tokens, Clock clock) {
        this.store = Objects.requireNonNull(store);
        this.settings = Objects.requireNonNull(settings);
        this.tokens = Objects.requireNonNull(tokens);
        this.clock = Objects.requireNonNull(clock);
        this.permits = new Semaphore(settings.maxInFlight());
    }

    @Override public void handle(HttpExchange exchange) throws IOException {
        if (!permits.tryAcquire()) { send(exchange, failure(429)); return; }
        long start = System.nanoTime();
        var result = new CompletableFuture<Result>();
        try {
            work.execute(() -> {
                try { result.complete(check(exchange, start)); }
                catch (Rejected rejected) { result.complete(failure(rejected.status)); }
                catch (Exception unavailable) { result.complete(failure(503)); }
                finally { permits.release(); }
            });
        } catch (RuntimeException closed) {
            permits.release();
            send(exchange, failure(503));
            return;
        }
        Result reply;
        try {
            long remaining = settings.requestTimeout().toNanos() - (System.nanoTime() - start);
            if (remaining <= 0) throw new Rejected(503);
            reply = result.get(remaining, TimeUnit.NANOSECONDS);
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            reply = failure(503);
        } catch (Exception unavailable) {
            reply = failure(503);
        }
        send(exchange, reply);
    }

    private Result check(HttpExchange exchange, long started) throws IOException {
        if (!PATH.equals(exchange.getRequestURI().getPath()) || exchange.getRequestURI().getQuery() != null
                || exchange.getRequestHeaders().containsKey("Cookie")) throw new Rejected(400);
        if (!"POST".equals(exchange.getRequestMethod())) throw new Rejected(403);
        String authorization = header(exchange, "Authorization", true);
        if (!authorization.startsWith("Bearer ")) throw new Rejected(401);
        final Jwt jwt;
        try {
            jwt = tokens.decode(authorization.substring(7));
            validateIdentity(jwt);
        } catch (RuntimeException invalid) { throw new Rejected(401); }
        final List<String> roles;
        try { roles = jwt.getClaimAsStringList("roles"); }
        catch (RuntimeException invalidRole) { throw new Rejected(403); }
        if (!settings.callerPrincipal().toString().equals(jwt.getClaimAsString("oid"))
                || !settings.callerClient().toString().equals(jwt.getClaimAsString("azp"))
                || roles == null || !roles.contains(settings.role())) throw new Rejected(403);
        String media = header(exchange, "Content-Type", true);
        if (!media.matches("(?i)application/json(?:\\s*;\\s*charset=utf-8)?")) throw new Rejected(415);
        String encoding = header(exchange, "Content-Encoding", false);
        if (encoding != null && !"identity".equalsIgnoreCase(encoding)) throw new Rejected(415);
        String trace = header(exchange, "X-Correlation-Id", true);
        if (!trace.matches("[A-Za-z0-9._:-]{1,128}")) throw new Rejected(400);
        byte[] bytes = exchange.getRequestBody().readNBytes(settings.maxRequestBytes() + 1);
        if (bytes.length > settings.maxRequestBytes()) throw new Rejected(413);
        final Request request;
        try { request = parse(bytes, trace); }
        catch (Exception invalid) { throw new Rejected(400); }
        Instant deadline = request.deadline().isBefore(jwt.getExpiresAt()) ? request.deadline() : jwt.getExpiresAt();
        long now = System.nanoTime();
        long remaining = Math.min(settings.requestTimeout().toNanos() - (now - started),
                Duration.between(clock.instant(), deadline).toNanos());
        if (remaining <= 0) throw new Rejected(503);
        long endNanos = now + remaining;
        var permittedScope = new EvidenceScope(settings.captureTenant(), settings.installationId(), request.query().scope().revision());
        var handler = new CheckEvidenceMembershipHandler(store, (operation, query) ->
                operation == EvidenceAuthority.Operation.CHECK_MEMBERSHIP
                        && permittedScope.equals(query.scope()) ? EvidenceAuthority.Decision.AUTHORIZED : EvidenceAuthority.Decision.DENIED);
        if (!"github_actions".equals(request.query().source())) throw new Rejected(400);
        String decision;
        if (!permittedScope.equals(request.query().scope())) {
            decision = "DENIED";
        } else {
            decision = switch (handler.handleScoped(request.query())) {
                case MATCH -> "AUTHORIZED";
                case NOT_READY -> "NOT_READY";
                case MISMATCH -> "MISMATCH";
            };
        }
        if (endNanos - System.nanoTime() <= 0 || !clock.instant().isBefore(deadline)) throw new Rejected(503);
        return new Result(200, Map.of("requestId", request.id().toString(), "correlationId", trace, "decision", decision));
    }

    private void validateIdentity(Jwt jwt) {
        Instant now = clock.instant();
        if (!"2.0".equals(jwt.getClaimAsString("ver")) || !"app".equals(jwt.getClaimAsString("idtyp"))
                || jwt.getClaim("scp") != null || jwt.getIssuer() == null
                || !settings.issuer().toString().equals(jwt.getIssuer().toString())
                || !jwt.getAudience().contains(settings.audience())
                || !settings.directoryTenant().toString().equals(jwt.getClaimAsString("tid"))
                || jwt.getExpiresAt() == null || !now.minus(settings.clockSkew()).isBefore(jwt.getExpiresAt())
                || jwt.getNotBefore() != null && now.plus(settings.clockSkew()).isBefore(jwt.getNotBefore())
                || jwt.getIssuedAt() == null || jwt.getIssuedAt().isAfter(now.plus(settings.clockSkew()))
                || jwt.getClaim("appid") != null && !jwt.getClaimAsString("appid").equals(jwt.getClaimAsString("azp"))) {
            throw new Rejected(401);
        }
    }

    private String header(HttpExchange exchange, String name, boolean required) {
        var values = exchange.getRequestHeaders().get(name);
        if (values == null) {
            if (!required) return null;
            throw new Rejected("Authorization".equals(name) ? 401 : 400);
        }
        if (values.size() != 1 || values.getFirst().isBlank() || values.getFirst().length() > settings.maxHeaderChars()) {
            throw new Rejected(400);
        }
        return values.getFirst();
    }

    private static Request parse(byte[] bytes, String trace) throws Exception {
        String text = StandardCharsets.UTF_8.newDecoder().onMalformedInput(CodingErrorAction.REPORT)
                .onUnmappableCharacter(CodingErrorAction.REPORT).decode(ByteBuffer.wrap(bytes)).toString();
        if (text.startsWith("\ufeff")) throw new Rejected(400);
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
        if (!id.toString().equals(raw) || !id(id)) throw new Rejected(400);
        return id;
    }

    private static String text(JsonNode json, String field) {
        var node = json.get(field);
        if (node == null || !node.isString() || node.asString().isBlank()) throw new Rejected(400);
        return node.asString();
    }

    private static boolean id(UUID value) { return value != null && !value.equals(new UUID(0, 0)); }
    private static boolean https(URI uri) {
        return uri != null && "https".equals(uri.getScheme()) && uri.getHost() != null
                && uri.getUserInfo() == null && uri.getQuery() == null && uri.getFragment() == null;
    }

    private static Result failure(int status) {
        String title = switch (status) {
            case 400 -> "Bad Request"; case 401 -> "Unauthorized"; case 403 -> "Forbidden";
            case 413 -> "Content Too Large"; case 415 -> "Unsupported Media Type"; case 429 -> "Too Many Requests";
            default -> "Service Unavailable";
        };
        String code = switch (status) {
            case 400 -> "INVALID_REQUEST"; case 401 -> "UNAUTHENTICATED"; case 403 -> "CALLER_DENIED";
            case 413 -> "REQUEST_TOO_LARGE"; case 415 -> "UNSUPPORTED_MEDIA_TYPE"; case 429 -> "OVERLOADED";
            default -> "UNAVAILABLE";
        };
        return new Result(status, Map.of("type", "about:blank", "title", title, "status", status, "code", code));
    }

    private static void send(HttpExchange exchange, Result result) throws IOException {
        try (exchange) {
            exchange.getResponseHeaders().set("Cache-Control", "no-store");
            exchange.getResponseHeaders().set("Content-Type", result.status() == 200 ? "application/json" : "application/problem+json");
            if (result.status() == 401) exchange.getResponseHeaders().set("WWW-Authenticate", "Bearer");
            byte[] bytes = JSON.writeValueAsBytes(result.body());
            exchange.sendResponseHeaders(result.status(), bytes.length);
            exchange.getResponseBody().write(bytes);
            exchange.getResponseBody().flush();
        }
    }

    private record Request(UUID id, Instant deadline, EvidenceMembershipQuery query) {}
    private record Result(int status, Map<String, ?> body) {}
    private static final class Rejected extends RuntimeException {
        final int status;
        Rejected(int status) { super(null, null, false, false); this.status = status; }
    }
    @Override public void close() { work.shutdownNow(); }
}
