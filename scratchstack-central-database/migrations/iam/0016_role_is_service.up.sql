--- Add a column to iam.roles to enable a role to be linked with a service.
ALTER TABLE iam.roles
ADD COLUMN is_service BOOLEAN NOT NULL DEFAULT FALSE;
