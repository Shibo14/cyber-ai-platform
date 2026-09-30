-- Destructive rollback: drops the tenant catalog and all membership rows.
DROP TABLE cyber.tenant_memberships;
DROP TABLE cyber.tenants;
