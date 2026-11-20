package org.pipesor.logevent.evidence.infrastructure.persistence.jdbc;

import org.pipesor.logevent.evidence.application.commands.EvidenceInput;
import org.pipesor.logevent.evidence.application.ports.EvidenceStore;
import org.pipesor.logevent.evidence.application.ports.EvidenceStoreUnavailableException;
import org.pipesor.logevent.evidence.application.queries.EvidenceMembershipQuery;

import javax.sql.DataSource;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.time.Clock;
import java.time.OffsetDateTime;
import java.time.ZoneOffset;
import java.time.temporal.ChronoUnit;
import java.util.Objects;
import java.util.UUID;

public final class JdbcEvidenceStore implements EvidenceStore {
    private final DataSource dataSource;
    private final Clock clock;

    public JdbcEvidenceStore(DataSource dataSource, Clock clock) {
        this.dataSource = Objects.requireNonNull(dataSource);
        this.clock = Objects.requireNonNull(clock);
    }

    @Override
    public Registration register(EvidenceInput input) {
        Objects.requireNonNull(input);
        try (var connection = dataSource.getConnection()) {
            connection.setTransactionIsolation(Connection.TRANSACTION_READ_COMMITTED);
            connection.setAutoCommit(false);
            try {
                var result = insert(connection, input) ? Registration.CREATED : compare(connection, input);
                connection.commit();
                return result;
            } catch (SQLException exception) {
                try {
                    connection.rollback();
                } catch (SQLException ignored) {
                    // The boundary reports only unavailability, without database or evidence details.
                }
                throw exception;
            }
        } catch (SQLException exception) {
            throw new EvidenceStoreUnavailableException();
        }
    }

    private boolean insert(Connection connection, EvidenceInput input) throws SQLException {
        try (var statement = connection.prepareStatement("""
                INSERT INTO evidence.evidence_items
                  (id, incident_id, execution_id, correlation_id, source, stage, job, summary,
                   excerpt, observed_at, sequence, content_hash, size_bytes, created_at,
                   scope_tenant_id, scope_github_installation_id, scope_revision, source_locator)
                VALUES (?, ?, ?, ?, ?, ?::evidence."PipelineStage", ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT (id) DO NOTHING
                """)) {
            statement.setObject(1, input.evidenceId());
            statement.setObject(2, input.incidentId());
            statement.setObject(3, input.executionId());
            statement.setString(4, input.correlationId());
            statement.setString(5, input.source());
            statement.setString(6, input.stage().name());
            statement.setString(7, input.job());
            statement.setString(8, input.summary());
            statement.setString(9, input.excerpt());
            statement.setObject(10, input.observedAt().atOffset(ZoneOffset.UTC));
            statement.setObject(11, input.sequence());
            statement.setString(12, input.contentHash());
            statement.setObject(13, input.sizeBytes());
            statement.setObject(14, clock.instant().truncatedTo(ChronoUnit.MICROS).atOffset(ZoneOffset.UTC));
            statement.setObject(15, input.scope() == null ? null : input.scope().tenantId());
            statement.setString(16, input.scope() == null ? null : input.scope().installationId());
            statement.setString(17, input.scope() == null ? null : input.scope().revision());
            statement.setString(18, input.sourceLocator());
            return statement.executeUpdate() == 1;
        }
    }

    private Registration compare(Connection connection, EvidenceInput input) throws SQLException {
        // A separate READ COMMITTED statement sees the winner after a concurrent insert finishes.
        try (var statement = connection.prepareStatement("""
                SELECT incident_id, execution_id, correlation_id, source, stage, job, summary,
                       excerpt, observed_at, sequence, content_hash, size_bytes,
                       scope_tenant_id, scope_github_installation_id, scope_revision, source_locator
                FROM evidence.evidence_items WHERE id = ?
                """)) {
            statement.setObject(1, input.evidenceId());
            try (var row = statement.executeQuery()) {
                if (!row.next()) throw new SQLException("Concurrent evidence unavailable");
                var equal = input.incidentId().equals(row.getObject("incident_id", UUID.class))
                        && input.executionId().equals(row.getObject("execution_id", UUID.class))
                        && input.correlationId().equals(row.getString("correlation_id"))
                        && input.source().equals(row.getString("source"))
                        && input.stage().name().equals(row.getString("stage"))
                        && Objects.equals(input.job(), row.getString("job"))
                        && input.summary().equals(row.getString("summary"))
                        && Objects.equals(input.excerpt(), row.getString("excerpt"))
                        && input.observedAt().equals(row.getObject("observed_at", OffsetDateTime.class).toInstant())
                        && Objects.equals(input.sequence(), row.getObject("sequence", Long.class))
                        && Objects.equals(input.sourceLocator(), row.getString("source_locator"))
                        && Objects.equals(input.contentHash(), row.getString("content_hash"))
                        && Objects.equals(input.sizeBytes(), row.getObject("size_bytes", Long.class))
                        && Objects.equals(input.scope() == null ? null : input.scope().tenantId(), row.getObject("scope_tenant_id", UUID.class))
                        && Objects.equals(input.scope() == null ? null : input.scope().installationId(), row.getString("scope_github_installation_id"))
                        && Objects.equals(input.scope() == null ? null : input.scope().revision(), row.getString("scope_revision"));
                return equal ? Registration.UNCHANGED : Registration.CONFLICT;
            }
        }
    }

    @Override
    public Membership membership(EvidenceMembershipQuery query) {
        Objects.requireNonNull(query);
        if (query.scope() != null) return scopedMembership(query);
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("""
                     SELECT incident_id, execution_id, source
                     FROM evidence.evidence_items WHERE id = ?
                     """)) {
            statement.setObject(1, query.evidenceId());
            try (var row = statement.executeQuery()) {
                if (!row.next()) return Membership.NOT_READY;
                return sameMembership(row, query) ? Membership.MATCH : Membership.MISMATCH;
            }
        } catch (SQLException exception) {
            throw new EvidenceStoreUnavailableException();
        }
    }

    private Membership scopedMembership(EvidenceMembershipQuery query) {
        try (var connection = dataSource.getConnection();
             var statement = connection.prepareStatement("""
                     SELECT source FROM evidence.evidence_items
                     WHERE id = ? AND scope_tenant_id = ? AND scope_github_installation_id = ?
                       AND scope_revision = ? AND execution_id = ? AND incident_id = ?
                     """)) {
            statement.setObject(1, query.evidenceId());
            statement.setObject(2, query.scope().tenantId());
            statement.setString(3, query.scope().installationId());
            statement.setString(4, query.scope().revision());
            statement.setObject(5, query.executionId());
            statement.setObject(6, query.incidentId());
            try (var row = statement.executeQuery()) {
                if (!row.next()) return Membership.NOT_READY;
                return query.source().equals(row.getString("source")) ? Membership.MATCH : Membership.MISMATCH;
            }
        } catch (SQLException exception) {
            throw new EvidenceStoreUnavailableException();
        }
    }

    private boolean sameMembership(ResultSet row, EvidenceMembershipQuery query) throws SQLException {
        return query.incidentId().equals(row.getObject("incident_id", UUID.class))
                && query.executionId().equals(row.getObject("execution_id", UUID.class))
                && query.source().equals(row.getString("source"));
    }
}
