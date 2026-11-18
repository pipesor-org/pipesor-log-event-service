package org.pipesor.logevent.evidence.infrastructure.authority;

import java.io.ByteArrayOutputStream;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.time.Clock;
import java.time.Duration;
import java.time.Instant;
import java.util.List;
import java.util.Objects;
import java.util.UUID;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.CompletionStage;
import java.util.concurrent.Flow;
import java.util.concurrent.TimeUnit;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority.Decision;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceIntake;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceV2;
import tools.jackson.core.StreamReadFeature;
import tools.jackson.databind.DeserializationFeature;
import tools.jackson.databind.JsonNode;
import tools.jackson.databind.json.JsonMapper;

/** Read-only Pipeline authority. Compose only with an authenticated evidence delivery channel. */
public final class HttpPipelineAuthority implements ProtectedEvidenceIntake.Authority {
    private static final String PATH = "/internal/v1/evidence/operational-reference-checks";
    private static final JsonMapper JSON = JsonMapper.builder()
            .enable(StreamReadFeature.STRICT_DUPLICATE_DETECTION)
            .enable(DeserializationFeature.FAIL_ON_TRAILING_TOKENS)
            .disable(StreamReadFeature.INCLUDE_SOURCE_IN_LOCATION)
            .build();

    @FunctionalInterface
    public interface TokenSource {
        /** Return a valid app-only token for Pipeline within the supplied remaining budget. */
        String acquire(Duration remaining);
    }

    private final HttpClient http;
    private final URI endpoint;
    private final TokenSource tokens;
    private final Clock clock;
    private final Duration timeout;
    private final int maxResponseBytes;

    public HttpPipelineAuthority(URI origin, TokenSource tokens, Duration timeout, int maxResponseBytes) {
        this(HttpClient.newBuilder().followRedirects(HttpClient.Redirect.NEVER).build(), origin,
                tokens, Clock.systemUTC(), timeout, maxResponseBytes);
    }

    HttpPipelineAuthority(HttpClient http, URI origin, TokenSource tokens, Clock clock,
            Duration timeout, int maxResponseBytes) {
        if (!"https".equals(origin.getScheme()) || origin.getHost() == null || origin.getRawUserInfo() != null
                || origin.getRawQuery() != null || origin.getRawFragment() != null
                || !List.of("", "/").contains(origin.getRawPath())
                || timeout.isZero() || timeout.isNegative() || maxResponseBytes < 1
                || http.followRedirects() != HttpClient.Redirect.NEVER) {
            throw new IllegalArgumentException("Invalid Pipeline authority configuration");
        }
        timeout.toNanos();
        this.endpoint = origin.resolve(PATH);
        this.http = http;
        this.tokens = Objects.requireNonNull(tokens);
        this.clock = Objects.requireNonNull(clock);
        this.timeout = timeout;
        this.maxResponseBytes = maxResponseBytes;
    }

    @Override
    public Decision verify(ProtectedEvidenceV2.Binding binding, EvidenceMembershipQuery references,
            String correlationId) {
        long start = System.nanoTime();
        CompletableFuture<HttpResponse<byte[]>> response = null;
        try {
            var requestId = UUID.randomUUID().toString();
            Instant deadline = clock.instant().plus(timeout);
            String token = tokens.acquire(remaining(start));
            var body = JSON.createObjectNode()
                    .put("requestId", requestId)
                    .put("correlationId", correlationId)
                    .put("deadlineAt", deadline.toString())
                    .put("tenantId", binding.tenantId().toString())
                    .put("githubAccountId", binding.githubAccountId())
                    .put("githubInstallationId", binding.githubInstallationId())
                    .put("githubRepositoryId", binding.githubRepositoryId())
                    .put("githubWorkflowId", binding.githubWorkflowId())
                    .put("scopeRevision", binding.scopeRevision())
                    .put("githubRunId", binding.githubRunId())
                    .put("runAttempt", binding.runAttempt())
                    .put("pipelineId", binding.pipelineId().toString())
                    .put("executionId", references.executionId().toString())
                    .put("incidentId", references.incidentId().toString());
            var request = HttpRequest.newBuilder(endpoint)
                    .timeout(remaining(start))
                    .header("Authorization", "Bearer " + Objects.requireNonNull(token))
                    .header("X-Correlation-Id", correlationId)
                    .header("Content-Type", "application/json")
                    .POST(HttpRequest.BodyPublishers.ofByteArray(JSON.writeValueAsBytes(body))).build();
            response = http.sendAsync(request, ignored -> new BoundedBody(maxResponseBytes));
            var received = response.get(remaining(start).toNanos(), TimeUnit.NANOSECONDS);
            if (received.statusCode() != 200 || !received.headers().allValues("Cache-Control").equals(List.of("no-store"))
                    || !received.headers().allValues("Content-Type").equals(List.of("application/json"))) {
                return Decision.UNAVAILABLE;
            }
            String decoded = StandardCharsets.UTF_8.newDecoder().decode(ByteBuffer.wrap(received.body())).toString();
            JsonNode result = JSON.readTree(decoded);
            if (result == null || !result.isObject() || result.size() != 3
                    || !requestId.equals(string(result, "requestId"))
                    || !correlationId.equals(string(result, "correlationId"))) {
                return Decision.UNAVAILABLE;
            }
            remaining(start);
            if (!clock.instant().isBefore(deadline)) return Decision.UNAVAILABLE;
            return switch (string(result, "decision")) {
                case "AUTHORIZED" -> Decision.AUTHORIZED;
                case "DENIED" -> Decision.DENIED;
                case "NOT_READY" -> Decision.NOT_READY;
                case "MISMATCH" -> Decision.MISMATCH;
                default -> Decision.UNAVAILABLE;
            };
        } catch (InterruptedException interrupted) {
            Thread.currentThread().interrupt();
            return Decision.UNAVAILABLE;
        } catch (Exception unavailable) {
            return Decision.UNAVAILABLE;
        } finally {
            if (response != null && !response.isDone()) response.cancel(true);
        }
    }

    private Duration remaining(long start) {
        long nanos = timeout.toNanos() - (System.nanoTime() - start);
        if (nanos <= 0) throw new IllegalStateException("Pipeline validation deadline exceeded");
        return Duration.ofNanos(nanos);
    }

    private static String string(JsonNode json, String name) {
        var node = json.get(name);
        return node != null && node.isString() ? node.asString() : "";
    }

    private static final class BoundedBody implements HttpResponse.BodySubscriber<byte[]> {
        private final CompletableFuture<byte[]> body = new CompletableFuture<>();
        private final ByteArrayOutputStream buffer = new ByteArrayOutputStream();
        private final int limit;
        private Flow.Subscription subscription;

        BoundedBody(int limit) { this.limit = limit; }

        @Override public CompletionStage<byte[]> getBody() { return body; }

        @Override public void onSubscribe(Flow.Subscription subscription) {
            this.subscription = subscription;
            subscription.request(1);
        }

        @Override public void onNext(List<ByteBuffer> items) {
            for (var item : items) {
                if (item.remaining() > limit - buffer.size()) {
                    subscription.cancel();
                    body.completeExceptionally(new IllegalStateException("Pipeline response exceeds configured size"));
                    return;
                }
                byte[] chunk = new byte[item.remaining()];
                item.get(chunk);
                buffer.writeBytes(chunk);
            }
            subscription.request(1);
        }

        @Override public void onError(Throwable error) { body.completeExceptionally(error); }

        @Override public void onComplete() { body.complete(buffer.toByteArray()); }
    }
}
