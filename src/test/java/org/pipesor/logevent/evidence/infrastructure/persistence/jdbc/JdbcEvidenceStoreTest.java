package org.pipesor.logevent.evidence.infrastructure.persistence.jdbc;

import org.flywaydb.core.Flyway;
import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;
import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.commandhandlers.RegisterEvidenceHandler;
import org.pipesor.logevent.evidence.application.ports.EvidenceAuthority;
import org.pipesor.logevent.evidence.interfaces.messaging.ProtectedEvidenceIntake;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore.Membership;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore.Registration;
import org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;
import org.pipesor.logevent.evidence.application.queryhandlers.CheckEvidenceMembershipHandler;
import org.pipesor.logevent.evidence.application.services.EvidenceAccessException;
import org.pipesor.logevent.evidence.domain.model.valueobjects.PipelineStage;
import org.pipesor.logevent.evidence.domain.model.valueobjects.EvidenceScope;
import org.postgresql.ds.PGSimpleDataSource;
import org.testcontainers.postgresql.PostgreSQLContainer;

import java.sql.SQLException;
import java.time.Clock;
import java.time.Instant;
import java.time.ZoneOffset;
import java.util.ArrayList;
import java.util.List;
import java.util.UUID;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static org.assertj.core.api.Assertions.assertThat;
import static org.junit.jupiter.api.Assertions.assertThrows;

class JdbcEvidenceStoreTest {
    private static final PostgreSQLContainer POSTGRES = new PostgreSQLContainer("postgres:17.11");
    private static final Instant CREATED = Instant.parse("2026-11-17T12:00:00.123456Z");
    private static PGSimpleDataSource dataSource;
    private static Flyway flyway;
    private static JdbcEvidenceStore store;

    @BeforeAll
    static void startDatabase() throws SQLException {
        POSTGRES.start();
        dataSource = new PGSimpleDataSource();
        dataSource.setURL(POSTGRES.getJdbcUrl());
        dataSource.setUser(POSTGRES.getUsername());
        dataSource.setPassword(POSTGRES.getPassword());
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.execute("CREATE SCHEMA evidence");
            // Synthetic neighboring context verifies that sharing its schema grants no ownership.
            statement.execute("CREATE TABLE evidence.correlated_contexts (marker text NOT NULL)");
            statement.execute("INSERT INTO evidence.correlated_contexts VALUES ('untouched')");
        }
        flyway = Flyway.configure().dataSource(dataSource).defaultSchema("evidence")
                .table("flyway_history_local_log_event").baselineOnMigrate(true).baselineVersion("0").load();
        assertThat(flyway.migrate().migrationsExecuted).isEqualTo(2);
        store = new JdbcEvidenceStore(dataSource, Clock.fixed(CREATED, ZoneOffset.UTC));
    }

    @AfterAll
    static void stopDatabase() {
        POSTGRES.stop();
    }

    @Test
    void migrationMatchesOwnedModelWithoutTouchingNeighborOrAddingForeignKeys() throws SQLException {
        flyway.validate();
        assertThat(flyway.migrate().migrationsExecuted).isZero();
        assertThat(strings("""
                SELECT column_name || ':' || udt_name || ':' || is_nullable
                FROM information_schema.columns
                WHERE table_schema = 'evidence' AND table_name = 'evidence_items'
                ORDER BY ordinal_position
                """)).containsExactly("id:uuid:NO", "incident_id:uuid:NO", "execution_id:uuid:NO",
                "correlation_id:text:NO", "source:text:NO", "stage:PipelineStage:NO", "job:text:YES",
                "summary:text:NO", "excerpt:text:YES", "observed_at:timestamptz:NO", "sequence:int8:YES",
                "content_hash:text:YES", "size_bytes:int8:YES", "created_at:timestamptz:NO",
                "scope_tenant_id:uuid:YES", "scope_github_installation_id:text:YES", "scope_revision:text:YES");
        assertThat(strings("SELECT marker FROM evidence.correlated_contexts")).containsExactly("untouched");
        assertThat(strings("""
                SELECT table_schema || '.' || table_name FROM information_schema.tables
                WHERE table_schema NOT IN ('pg_catalog', 'information_schema') ORDER BY table_name
                """)).containsExactly("evidence.correlated_contexts", "evidence.evidence_items",
                "evidence.flyway_history_local_log_event");
        assertThat(strings("""
                SELECT constraint_name FROM information_schema.table_constraints
                WHERE table_schema = 'evidence' AND table_name = 'evidence_items'
                  AND constraint_type = 'FOREIGN KEY'
                """)).isEmpty();
        assertThat(strings("""
                SELECT e.enumlabel FROM pg_enum e JOIN pg_type t ON t.oid = e.enumtypid
                JOIN pg_namespace n ON n.oid = t.typnamespace
                WHERE n.nspname = 'evidence' AND t.typname = 'PipelineStage' ORDER BY e.enumsortorder
                """)).containsExactly("BUILD", "TESTING", "QUALITY_GATE", "DEPLOYMENT", "CONTAINER", "INFRASTRUCTURE");
    }

    @Test
    void roundTripPreservesProvenanceMicrosecondsAndLargeSequence() throws SQLException {
        var input = input(UUID.randomUUID());
        assertThat(store.register(input)).isEqualTo(Registration.CREATED);
        assertThat(row(input)).containsExactly(input.evidenceId(), input.incidentId(), input.executionId(),
                input.correlationId(), input.source(), input.stage().name(), input.job(), input.summary(),
                input.excerpt(), input.observedAt(), input.sequence(), input.contentHash(), input.sizeBytes(), CREATED);
        assertThat(input.observedAt()).isEqualTo(Instant.parse("2026-11-08T09:20:31.123456Z"));
        assertThat(store.membership(query(input))).isEqualTo(Membership.MATCH);
    }

    @Test
    void duplicateRetainsFirstTechnicalTimeAndEveryFieldChangeConflictsWithoutMutation() throws SQLException {
        var original = input(UUID.randomUUID());
        assertThat(store.register(original)).isEqualTo(Registration.CREATED);
        var saved = row(original);
        var later = new JdbcEvidenceStore(dataSource, Clock.fixed(CREATED.plusSeconds(60), ZoneOffset.UTC));
        assertThat(later.register(original)).isEqualTo(Registration.UNCHANGED);
        var variants = List.of(
                change(original, UUID.randomUUID(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), UUID.randomUUID(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), "correlation-other", original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), "github_actions", original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), PipelineStage.BUILD, original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), null, original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), "Other synthetic summary", original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), null, original.observedAt(), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt().plusNanos(1000), original.sequence(), original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), null, original.contentHash(), original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), null, original.sizeBytes()),
                change(original, original.incidentId(), original.executionId(), original.correlationId(), original.source(), original.stage(), original.job(), original.summary(), original.excerpt(), original.observedAt(), original.sequence(), original.contentHash(), null));
        for (var changed : variants) {
            assertThat(later.register(changed)).isEqualTo(Registration.CONFLICT);
            assertThat(row(original)).isEqualTo(saved);
        }
    }

    @Test
    void optionalFieldsRoundTripAndNegativeSizeIsAlsoRejectedByDatabase() throws SQLException {
        var full = input(UUID.randomUUID());
        var minimal = change(full, full.incidentId(), full.executionId(), full.correlationId(), full.source(), full.stage(),
                null, full.summary(), null, full.observedAt(), null, null, null);
        assertThat(store.register(minimal)).isEqualTo(Registration.CREATED);
        assertThat(store.register(minimal)).isEqualTo(Registration.UNCHANGED);
        try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("""
                INSERT INTO evidence.evidence_items
                    (id, incident_id, execution_id, correlation_id, source, stage, job, summary,
                     excerpt, observed_at, sequence, content_hash, size_bytes, created_at)
                SELECT ?, incident_id, execution_id, correlation_id, source, stage, job, summary,
                       excerpt, observed_at, sequence, content_hash, -1, created_at
                FROM evidence.evidence_items WHERE id = ?
                """)) {
            statement.setObject(1, UUID.randomUUID());
            statement.setObject(2, minimal.evidenceId());
            assertThat(assertThrows(SQLException.class, statement::executeUpdate).getSQLState()).isEqualTo("23514");
        }
    }

    @Test
    void similarSignalsFromUnrelatedExecutionsRemainSeparateAndMembershipChecksAllReferences() {
        var first = input(UUID.randomUUID());
        var second = input(UUID.randomUUID());
        assertThat(store.register(first)).isEqualTo(Registration.CREATED);
        assertThat(store.register(second)).isEqualTo(Registration.CREATED);
        assertThat(store.membership(query(first))).isEqualTo(Membership.MATCH);
        assertThat(store.membership(query(second))).isEqualTo(Membership.MATCH);
        assertThat(store.membership(new EvidenceMembershipQuery(first.evidenceId(), second.incidentId(), first.executionId(), first.source())))
                .isEqualTo(Membership.MISMATCH);
        assertThat(store.membership(new EvidenceMembershipQuery(first.evidenceId(), first.incidentId(), second.executionId(), first.source())))
                .isEqualTo(Membership.MISMATCH);
        assertThat(store.membership(new EvidenceMembershipQuery(first.evidenceId(), first.incidentId(), first.executionId(), "github_actions")))
                .isEqualTo(Membership.MISMATCH);
        assertThat(store.membership(new EvidenceMembershipQuery(UUID.randomUUID(), first.incidentId(), first.executionId(), first.source())))
                .isEqualTo(Membership.NOT_READY);
    }

    @Test
    void concurrentEqualRegistrationHasOneWinnerAndConcurrentConflictNeverOverwrites() throws Exception {
        var same = input(UUID.randomUUID());
        var results = concurrent(List.of(same, same, same, same, same, same, same, same));
        assertThat(results).containsOnly(Registration.CREATED, Registration.UNCHANGED);
        assertThat(results.stream().filter(value -> value == Registration.CREATED).count()).isEqualTo(1);
        var first = input(UUID.randomUUID());
        var changed = change(first, first.incidentId(), first.executionId(), first.correlationId(), first.source(), first.stage(),
                first.job(), "Different synthetic summary", first.excerpt(), first.observedAt(), first.sequence(), first.contentHash(), first.sizeBytes());
        assertThat(concurrent(List.of(first, changed))).containsExactlyInAnyOrder(Registration.CREATED, Registration.CONFLICT);
        var originalRow = row(first);
        assertThat(originalRow.get(7)).isIn(first.summary(), changed.summary());
        assertThat(store.register(first)).isIn(Registration.UNCHANGED, Registration.CONFLICT);
        assertThat(store.register(changed)).isIn(Registration.UNCHANGED, Registration.CONFLICT);
        assertThat(row(first)).isEqualTo(originalRow);
    }

    @Test
    void databaseErrorsDoNotExposeSqlOrConnectionDetails() {
        var unavailable = new PGSimpleDataSource();
        unavailable.setURL(POSTGRES.getJdbcUrl());
        unavailable.setUser(POSTGRES.getUsername());
        unavailable.setPassword(POSTGRES.getPassword());
        unavailable.setDatabaseName("synthetic_missing_database");
        var failing = new JdbcEvidenceStore(unavailable, Clock.systemUTC());
        var input = input(UUID.randomUUID());
        var failure = assertThrows(EvidenceStoreUnavailableException.class, () -> failing.register(input));
        assertThat(failure.getMessage()).isEqualTo("Evidence store unavailable");
        assertThat(failure.getCause()).isNull();
        assertThrows(EvidenceStoreUnavailableException.class, () -> failing.membership(query(input)));
    }

    @Test
    void applicationBoundaryUsesRealStoreAfterAuthorizationAndDeniesBeforeAnyConnection() {
        EvidenceAuthority allowed = (operation, context) -> EvidenceAuthority.Decision.AUTHORIZED;
        var register = new RegisterEvidenceHandler(store, allowed);
        var membership = new CheckEvidenceMembershipHandler(store, allowed);
        var input = input(UUID.randomUUID());
        var registered = register.handle(input);
        assertThat(registered.evidenceId()).isEqualTo(input.evidenceId());
        assertThat(registered.state()).isEqualTo(Registration.CREATED);
        assertThat(register.handle(input).state()).isEqualTo(Registration.UNCHANGED);
        assertThat(membership.handle(query(input))).isEqualTo(Membership.MATCH);
        assertThat(membership.handle(new EvidenceMembershipQuery(UUID.randomUUID(), input.incidentId(), input.executionId(), input.source())))
                .isEqualTo(Membership.NOT_READY);
        assertThat(membership.handle(new EvidenceMembershipQuery(input.evidenceId(), UUID.randomUUID(), input.executionId(), input.source())))
                .isEqualTo(Membership.MISMATCH);

        var unusable = new JdbcEvidenceStore(new PGSimpleDataSource(), Clock.systemUTC());
        EvidenceAuthority denied = (operation, context) -> EvidenceAuthority.Decision.DENIED;
        var rejectedRegistration = new RegisterEvidenceHandler(unusable, denied);
        var rejectedMembership = new CheckEvidenceMembershipHandler(unusable, denied);
        assertThat(assertThrows(EvidenceAccessException.class, () -> rejectedRegistration.handle(input)).decision())
                .isEqualTo(EvidenceAuthority.Decision.DENIED);
        assertThat(assertThrows(EvidenceAccessException.class, () -> rejectedMembership.handle(query(input))).decision())
                .isEqualTo(EvidenceAuthority.Decision.DENIED);
    }

    @Test
    void ingestsTheActualProducerFixtureOnlyAfterAuthorityConfirmsItsBinding() throws Exception {
        byte[] body;
        try (var fixture = JdbcEvidenceStoreTest.class.getResourceAsStream("/protected-workflow-evidence-v2.json")) {
            body = java.util.Objects.requireNonNull(fixture).readAllBytes();
        }
        String messageId = "cf6b69cf-a28d-49f3-bceb-000000000001";
        String trace = "ci-investigation-204";
        String type = "protected_workflow_evidence";
        var expected = UUID.fromString("e6988490-6322-590d-b48d-662b154b55d9");
        var decision = new java.util.concurrent.atomic.AtomicReference<>(EvidenceAuthority.Decision.NOT_READY);
        var intake = new ProtectedEvidenceIntake(store, (binding, refs, validatedTrace) -> {
            assertThat(validatedTrace).isEqualTo(trace);
            assertThat(refs.evidenceId()).isEqualTo(expected);
            assertThat(refs.scope()).isEqualTo(new EvidenceScope(binding.tenantId(),
                    binding.githubInstallationId(), binding.scopeRevision()));
            assertThat(refs.executionId()).isEqualTo(UUID.fromString("9306afb1-dafe-5915-bded-b9ba5237985a"));
            assertThat(refs.incidentId()).isEqualTo(UUID.fromString("6b14d1b6-fce1-5fe1-8286-8ae6977b3dd0"));
            assertThat(binding.tenantId()).isEqualTo(UUID.fromString("d91d1df6-ae89-40c2-99b5-20edfb3e9ed0"));
            assertThat(binding.githubAccountId()).isEqualTo("6802100000000000000000000");
            assertThat(binding.githubInstallationId()).isEqualTo("7710600000000000000000000");
            assertThat(binding.scopeRevision()).isEqualTo("scope-rev-12");
            assertThat(binding.occurredAt()).isEqualTo(Instant.parse("2026-11-08T09:20:31.123456789Z"));
            assertThat(binding.sourceUpdatedAt()).isEqualTo(Instant.parse("2026-11-08T09:20:40.987654321Z"));
            return decision.get();
        }, body.length);
        var pending = assertThrows(EvidenceAccessException.class,
                () -> intake.receive(body, messageId, trace, type, 2));
        assertThat(pending.decision()).isEqualTo(EvidenceAuthority.Decision.NOT_READY);
        assertThat(strings("SELECT id::text FROM evidence.evidence_items")).doesNotContain(expected.toString());
        decision.set(EvidenceAuthority.Decision.AUTHORIZED);
        assertThat(intake.receive(body, messageId, trace, type, 2).state()).isEqualTo(Registration.CREATED);
        assertThat(intake.receive(body, messageId, trace, type, 2).state()).isEqualTo(Registration.UNCHANGED);
        decision.set(EvidenceAuthority.Decision.DENIED);
        var revoked = assertThrows(EvidenceAccessException.class,
                () -> intake.receive(body, messageId, trace, type, 2));
        assertThat(revoked.decision()).isEqualTo(EvidenceAuthority.Decision.DENIED);
        assertThat(strings("SELECT observed_at AT TIME ZONE 'UTC' FROM evidence.evidence_items WHERE id = '" + expected + "'::uuid"))
                .containsExactly("2026-11-08 09:20:31.123456");
        assertThat(strings("SELECT count(*)::text FROM evidence.evidence_items WHERE id = '" + expected + "'::uuid"))
                .containsExactly("1");
        assertThat(strings("SELECT scope_revision FROM evidence.evidence_items WHERE id = '" + expected + "'::uuid"))
                .containsExactly("scope-rev-12");
    }

    @Test
    void scopedMembershipHidesAbsentLegacyAndCrossedRowsBeforeComparingSource() {
        var scope = new EvidenceScope(UUID.randomUUID(), "7710600000000000000000000", "scope-r1");
        var scoped = scoped(input(UUID.randomUUID()), scope);
        var legacy = input(UUID.randomUUID());
        assertThat(store.register(scoped)).isEqualTo(Registration.CREATED);
        assertThat(store.register(legacy)).isEqualTo(Registration.CREATED);
        var handler = new CheckEvidenceMembershipHandler(store,
                (operation, query) -> EvidenceAuthority.Decision.AUTHORIZED);
        assertThat(handler.handleScoped(query(scoped))).isEqualTo(Membership.MATCH);
        for (var denied : List.of(
                new EvidenceMembershipQuery(UUID.randomUUID(), scoped.incidentId(), scoped.executionId(), scoped.source(), scope),
                new EvidenceMembershipQuery(legacy.evidenceId(), legacy.incidentId(), legacy.executionId(), legacy.source(), scope),
                new EvidenceMembershipQuery(scoped.evidenceId(), scoped.incidentId(), scoped.executionId(), scoped.source(),
                        new EvidenceScope(UUID.randomUUID(), scope.installationId(), scope.revision())),
                new EvidenceMembershipQuery(scoped.evidenceId(), scoped.incidentId(), scoped.executionId(), scoped.source(),
                        new EvidenceScope(scope.tenantId(), "77107", scope.revision())),
                new EvidenceMembershipQuery(scoped.evidenceId(), scoped.incidentId(), scoped.executionId(), scoped.source(),
                        new EvidenceScope(scope.tenantId(), scope.installationId(), "scope-r2")),
                new EvidenceMembershipQuery(scoped.evidenceId(), UUID.randomUUID(), scoped.executionId(), scoped.source(), scope),
                new EvidenceMembershipQuery(scoped.evidenceId(), scoped.incidentId(), UUID.randomUUID(), scoped.source(), scope))) {
            assertThat(handler.handleScoped(denied)).isEqualTo(Membership.NOT_READY);
        }
        assertThat(handler.handleScoped(new EvidenceMembershipQuery(scoped.evidenceId(), scoped.incidentId(),
                scoped.executionId(), "different-source", scope))).isEqualTo(Membership.MISMATCH);
        assertThrows(NullPointerException.class, () -> handler.handleScoped(query(legacy)));
        var unavailable = new JdbcEvidenceStore(new PGSimpleDataSource(), Clock.systemUTC());
        var rejected = new CheckEvidenceMembershipHandler(unavailable,
                (operation, query) -> EvidenceAuthority.Decision.DENIED);
        assertThat(assertThrows(EvidenceAccessException.class, () -> rejected.handleScoped(query(scoped))).decision())
                .isEqualTo(EvidenceAuthority.Decision.DENIED);
    }

    @Test
    void scopeIsFrozenOnReplayAndLegacyRowsCannotBeInferredFromTheNewRequest() throws Exception {
        var scope = new EvidenceScope(UUID.randomUUID(), "77106", "scope-r1");
        var original = scoped(input(UUID.randomUUID()), scope);
        assertThat(store.register(original)).isEqualTo(Registration.CREATED);
        assertThat(store.register(original)).isEqualTo(Registration.UNCHANGED);
        for (var alternative : List.of(
                new EvidenceScope(UUID.randomUUID(), scope.installationId(), scope.revision()),
                new EvidenceScope(scope.tenantId(), "77107", scope.revision()),
                new EvidenceScope(scope.tenantId(), scope.installationId(), "scope-r2"))) {
            assertThat(store.register(scoped(original, alternative))).isEqualTo(Registration.CONFLICT);
        }
        assertThat(store.register(scoped(original, null))).isEqualTo(Registration.CONFLICT);
        assertThat(store.membership(query(original))).isEqualTo(Membership.MATCH);
        var legacy = input(UUID.randomUUID());
        assertThat(store.register(legacy)).isEqualTo(Registration.CREATED);
        assertThat(store.register(scoped(legacy, scope))).isEqualTo(Registration.CONFLICT);
        assertThat(store.membership(query(scoped(legacy, scope)))).isEqualTo(Membership.NOT_READY);
        var racing = scoped(input(UUID.randomUUID()), scope);
        var other = scoped(racing, new EvidenceScope(scope.tenantId(), scope.installationId(), "scope-r2"));
        assertThat(concurrent(List.of(racing, other))).containsExactlyInAnyOrder(Registration.CREATED, Registration.CONFLICT);
        assertThat(List.of(store.membership(query(racing)), store.membership(query(other))))
                .containsExactlyInAnyOrder(Membership.MATCH, Membership.NOT_READY);
    }

    @Test
    void scopeMigrationPreservesV1RowsAndRejectsPartialBindings() throws Exception {
        var isolated = new PGSimpleDataSource();
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement()) {
            statement.execute("CREATE DATABASE legacy_scope_migration");
        }
        isolated.setURL(POSTGRES.getJdbcUrl().replace(POSTGRES.getDatabaseName(), "legacy_scope_migration"));
        isolated.setUser(POSTGRES.getUsername());
        isolated.setPassword(POSTGRES.getPassword());
        Flyway.configure().dataSource(isolated).defaultSchema("evidence").target("1").load().migrate();
        var legacyStore = new JdbcEvidenceStore(isolated, Clock.fixed(CREATED, ZoneOffset.UTC));
        var legacy = input(UUID.randomUUID());
        try (var connection = isolated.getConnection(); var statement = connection.prepareStatement("""
                INSERT INTO evidence.evidence_items
                    (id, incident_id, execution_id, correlation_id, source, stage, summary, observed_at, created_at)
                VALUES (?, ?, ?, ?, ?, ?::evidence."PipelineStage", ?, ?, ?)
                """)) {
            statement.setObject(1, legacy.evidenceId());
            statement.setObject(2, legacy.incidentId());
            statement.setObject(3, legacy.executionId());
            statement.setString(4, legacy.correlationId());
            statement.setString(5, legacy.source());
            statement.setString(6, legacy.stage().name());
            statement.setString(7, legacy.summary());
            statement.setObject(8, legacy.observedAt().atOffset(ZoneOffset.UTC));
            statement.setObject(9, CREATED.atOffset(ZoneOffset.UTC));
            statement.executeUpdate();
        }
        assertThat(Flyway.configure().dataSource(isolated).defaultSchema("evidence").load().migrate().migrationsExecuted)
                .isEqualTo(1);
        try (var connection = isolated.getConnection(); var statement = connection.prepareStatement("""
                SELECT summary, scope_tenant_id, scope_github_installation_id, scope_revision
                FROM evidence.evidence_items WHERE id = ?
                """)) {
            statement.setObject(1, legacy.evidenceId());
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                assertThat(rows.getString("summary")).isEqualTo(legacy.summary());
                assertThat(rows.getObject("scope_tenant_id")).isNull();
                assertThat(rows.getString("scope_github_installation_id")).isNull();
                assertThat(rows.getString("scope_revision")).isNull();
                assertThat(rows.next()).isFalse();
            }
        }
        var scope = new EvidenceScope(UUID.randomUUID(), "77106", "scope-r1");
        assertThat(legacyStore.membership(query(scoped(legacy, scope)))).isEqualTo(Membership.NOT_READY);
        try (var connection = isolated.getConnection(); var statement = connection.prepareStatement(
                "UPDATE evidence.evidence_items SET scope_tenant_id = ? WHERE id = ?")) {
            statement.setObject(1, scope.tenantId());
            statement.setObject(2, legacy.evidenceId());
            assertThat(assertThrows(SQLException.class, statement::executeUpdate).getSQLState()).isEqualTo("23514");
        }
    }

    private static EvidenceInput scoped(EvidenceInput input, EvidenceScope scope) {
        return new EvidenceInput(input.messageId(), input.incidentId(), input.executionId(), input.correlationId(),
                input.source(), input.stage(), input.job(), input.summary(), input.excerpt(), input.observedAt(),
                input.sequence(), input.contentHash(), input.sizeBytes(), scope);
    }

    private static List<Registration> concurrent(List<EvidenceInput> inputs) throws Exception {
        try (var executor = Executors.newFixedThreadPool(inputs.size())) {
            var start = new CountDownLatch(1);
            var futures = inputs.stream().map(input -> executor.submit(() -> {
                if (!start.await(10, TimeUnit.SECONDS)) throw new IllegalStateException("Test start timed out");
                return store.register(input);
            })).toList();
            start.countDown();
            var results = new ArrayList<Registration>();
            for (var future : futures) results.add(future.get(20, TimeUnit.SECONDS));
            return results;
        }
    }

    private static List<String> strings(String sql) throws SQLException {
        try (var connection = dataSource.getConnection(); var statement = connection.createStatement(); var rows = statement.executeQuery(sql)) {
            var result = new ArrayList<String>();
            while (rows.next()) result.add(rows.getString(1));
            return result;
        }
    }

    private static List<Object> row(EvidenceInput input) throws SQLException {
        try (var connection = dataSource.getConnection(); var statement = connection.prepareStatement("SELECT * FROM evidence.evidence_items WHERE id = ?")) {
            statement.setObject(1, input.evidenceId());
            try (var rows = statement.executeQuery()) {
                assertThat(rows.next()).isTrue();
                var result = new ArrayList<Object>();
                for (var i = 1; i <= 14; i++) {
                    if (i == 10 || i == 14) result.add(rows.getTimestamp(i).toInstant());
                    else if (i == 6) result.add(rows.getString(i));
                    else result.add(rows.getObject(i));
                }
                assertThat(rows.next()).isFalse();
                return result;
            }
        }
    }

    private static EvidenceInput input(UUID messageId) {
        return new EvidenceInput(messageId, UUID.randomUUID(), UUID.randomUUID(), "corr-synthetic-1", "github",
                PipelineStage.INFRASTRUCTURE, "job-redacted", "Synthetic failure [redacted]", "Synthetic trace [redacted]",
                Instant.parse("2026-11-08T09:20:31.123456789Z"), 4294967303L, "synthetic-content-digest", 99L);
    }

    private static EvidenceMembershipQuery query(EvidenceInput input) {
        return new EvidenceMembershipQuery(input.evidenceId(), input.incidentId(), input.executionId(), input.source(), input.scope());
    }

    private static EvidenceInput change(EvidenceInput original, UUID incidentId, UUID executionId, String correlationId,
                                        String source, PipelineStage stage, String job, String summary, String excerpt,
                                        Instant observedAt, Long sequence, String contentHash, Long sizeBytes) {
        return new EvidenceInput(original.messageId(), incidentId, executionId, correlationId, source, stage, job, summary,
                excerpt, observedAt, sequence, contentHash, sizeBytes);
    }
}
