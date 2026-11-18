ALTER TABLE evidence.evidence_items
    ADD COLUMN scope_tenant_id uuid,
    ADD COLUMN scope_github_installation_id text,
    ADD COLUMN scope_revision text,
    ADD CONSTRAINT evidence_items_scope_binding_ck CHECK (
        (scope_tenant_id IS NULL AND scope_github_installation_id IS NULL AND scope_revision IS NULL)
        OR (scope_tenant_id IS NOT NULL
            AND scope_tenant_id <> '00000000-0000-0000-0000-000000000000'::uuid
            AND scope_github_installation_id IS NOT NULL
            AND scope_github_installation_id ~ '^[1-9][0-9]*$'
            AND scope_revision IS NOT NULL
            AND scope_revision ~ '^[A-Za-z0-9._:-]{1,128}$')
    );
