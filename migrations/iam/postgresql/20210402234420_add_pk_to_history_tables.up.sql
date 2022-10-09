-- Add missing PKs to history tables
-- Add missing managed_policy_version and history table.
-- Add last_version to manged_policy table.

ALTER TABLE iam.deleted_iam_group
ADD CONSTRAINT pk_deleted_iam_group
PRIMARY KEY (group_id);

ALTER TABLE iam.deleted_iam_role
ADD CONSTRAINT pk_deleted_iam_role
PRIMARY KEY (role_id);

ALTER TABLE iam.deleted_iam_user
ADD CONSTRAINT pk_deleted_iam_user
PRIMARY KEY (user_id);

ALTER TABLE iam.deleted_managed_policy
ADD CONSTRAINT pk_deleted_managed_policy
PRIMARY KEY (managed_policy_id);

ALTER TABLE iam.managed_policy
ADD COLUMN last_version BIGINT;

CREATE TABLE iam.managed_policy_version(
    managed_policy_id           CHAR(16) NOT NULL,
    managed_policy_version      BIGINT NOT NULL,
    policy_document             TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_managed_policy_version PRIMARY KEY (managed_policy_id, managed_policy_version),
    CONSTRAINT fk_managed_policy_version_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policy(managed_policy_id)
);

CREATE TABLE iam.deleted_managed_policy_version(
    managed_policy_id           CHAR(16) NOT NULL,
    managed_policy_version      BIGINT NOT NULL,
    policy_document             TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    deleted_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_deleted_managed_policy_version PRIMARY KEY (managed_policy_id, managed_policy_version)
);

CREATE FUNCTION iam.on_delete_managed_policy_version() RETURNS TRIGGER AS $body$
BEGIN
    INSERT INTO iam.deleted_managed_policy_version(
        managed_policy_id, managed_policy_version, policy_document, created_at,
        deleted_at)
    VALUES(
        old.managed_policy_id, old.managed_policy_version, old.policy_document,
        old.created_at, CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    RETURN old;
END
$body$ LANGUAGE plpgsql;

CREATE TRIGGER trig_delete_managed_policy_version
AFTER DELETE ON iam.managed_policy_version
FOR EACH ROW
EXECUTE FUNCTION iam.on_delete_managed_policy_version();
