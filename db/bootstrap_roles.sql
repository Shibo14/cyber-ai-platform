-- Run once by a database administrator before applying migrations.
-- Application and migration login principals are provisioned separately.
-- Grant cyber_runtime to the application login and cyber_migrator to the
-- dedicated migration login. Do not grant either role to tenant-facing users.

DO $bootstrap$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cyber_runtime') THEN
        EXECUTE 'CREATE ROLE cyber_runtime NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS';
    END IF;

    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'cyber_migrator') THEN
        EXECUTE 'CREATE ROLE cyber_migrator NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS';
    END IF;
END
$bootstrap$;

CREATE SCHEMA IF NOT EXISTS cyber AUTHORIZATION cyber_migrator;
ALTER SCHEMA cyber OWNER TO cyber_migrator;
GRANT USAGE ON SCHEMA cyber TO cyber_runtime;
