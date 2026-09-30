CREATE TABLE cyber.tenants (
    tenant_id UUID PRIMARY KEY
);

CREATE TABLE cyber.tenant_memberships (
    tenant_id UUID NOT NULL REFERENCES cyber.tenants (tenant_id) ON DELETE CASCADE,
    principal_id TEXT NOT NULL CHECK (length(btrim(principal_id)) > 0),
    PRIMARY KEY (tenant_id, principal_id)
);

ALTER TABLE cyber.tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE cyber.tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenants_tenant_isolation
    ON cyber.tenants
    TO cyber_runtime
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

ALTER TABLE cyber.tenant_memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE cyber.tenant_memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_memberships_tenant_isolation
    ON cyber.tenant_memberships
    TO cyber_runtime
    USING (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid)
    WITH CHECK (tenant_id = NULLIF(current_setting('app.tenant_id', true), '')::uuid);

-- Runtime reads are limited to the active tenant. Membership and tenant
-- provisioning writes remain outside this foundation until their workflow is
-- defined. RLS policies still scope any separately-authorized writes.
GRANT SELECT ON cyber.tenants, cyber.tenant_memberships TO cyber_runtime;
