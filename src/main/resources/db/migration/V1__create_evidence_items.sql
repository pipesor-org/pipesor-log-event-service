CREATE SCHEMA IF NOT EXISTS evidence;

CREATE TYPE evidence."PipelineStage" AS ENUM (
    'BUILD', 'TESTING', 'QUALITY_GATE', 'DEPLOYMENT', 'CONTAINER', 'INFRASTRUCTURE'
);

CREATE TABLE evidence.evidence_items (
    id uuid PRIMARY KEY NOT NULL,
    incident_id uuid NOT NULL,
    execution_id uuid NOT NULL,
    correlation_id text NOT NULL,
    source text NOT NULL,
    stage evidence."PipelineStage" NOT NULL,
    job text,
    summary text NOT NULL,
    excerpt text,
    observed_at timestamptz NOT NULL,
    sequence bigint,
    content_hash text,
    size_bytes bigint,
    created_at timestamptz NOT NULL,
    CONSTRAINT evidence_items_check_1 CHECK (size_bytes IS NULL OR size_bytes >= 0)
);
