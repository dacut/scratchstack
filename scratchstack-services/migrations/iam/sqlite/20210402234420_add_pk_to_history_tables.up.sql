-- Add missing PKs to history tables.
DROP TRIGGER IF EXISTS trig_delete_iam_group;
DROP TRIGGER IF EXISTS trig_delete_iam_role;
DROP TRIGGER IF EXISTS trig_delete_iam_user;
DROP TRIGGER IF EXISTS trig_delete_managed_policy;

-- Add PK to deleted_iam_group. In SQLite, this requires creating a new table.
CREATE TABLE deleted_iam_group_v2(
    group_id                    CHAR(16),
    account_id                  CHAR(12),
    group_name_lower            VARCHAR(64),
    group_name_cased            VARCHAR(64),
    path                        VARCHAR(512),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6),
    CONSTRAINT pk_deleted_iam_group PRIMARY KEY (group_id)
);
INSERT OR IGNORE INTO deleted_iam_group_v2(
    group_id, account_id, group_name_lower, group_name_cased, path, created_at, deleted_at)
    SELECT group_id, account_id, group_name_lower, group_name_cased, path, created_at, deleted_at
    FROM deleted_iam_group;
ALTER TABLE deleted_iam_group RENAME TO deleted_iam_group_v1;
ALTER TABLE deleted_iam_group_v2 RENAME TO deleted_iam_group;
CREATE TRIGGER trig_delete_iam_group
AFTER DELETE ON iam_group
FOR EACH ROW
BEGIN
    INSERT INTO deleted_iam_group(
        group_id, account_id, group_name_lower, group_name_cased,
        path, created_at, deleted_at)
    VALUES(
        old.group_id, old.account_id, old.group_name_lower, old.group_name_cased,
        old.path, old.created_at, datetime('now'));
END;
DROP TABLE IF EXISTS deleted_iam_group_v1;

-- Add PK to deleted_iam_role. In SQLite, this requires creating a new table.
CREATE TABLE deleted_iam_role_v2(
    role_id                     CHAR(16),
    account_id                  CHAR(12),
    role_name_lower             VARCHAR(64),
    role_name_cased             VARCHAR(64),
    path                        VARCHAR(512),
    permissions_boundary_managed_policy_id CHAR(16),
    description                 VARCHAR(1000),
    assume_role_policy_document TEXT,
    created_at                  TIMESTAMP(6),
    CONSTRAINT pk_deleted_iam_role PRIMARY KEY (role_id)
);
INSERT OR IGNORE INTO deleted_iam_role_v2(
    role_id, account_id, role_name_lower, role_name_cased, path, permissions_boundary_managed_policy_id, description,
    assume_role_policy_document, created_at)
    SELECT role_id, account_id, role_name_lower, role_name_cased, path, permissions_boundary_managed_policy_id,
    description, assume_role_policy_document, created_at
    FROM deleted_iam_role;
ALTER TABLE deleted_iam_role RENAME TO deleted_iam_role_v1;
ALTER TABLE deleted_iam_role_v2 RENAME TO deleted_iam_role;
CREATE TRIGGER trig_delete_iam_role
AFTER DELETE ON iam_role
FOR EACH ROW
BEGIN
    INSERT INTO deleted_iam_role(
        role_id, account_id, role_name_lower, role_name_cased,
        path, permissions_boundary_managed_policy_id, description,
        assume_role_policy_document, created_at, deleted_at)
    VALUES(
        old.role_id, old.account_id, old.role_name_lower, old.role_name_cased,
        old.path, old.permissions_boundary_managed_policy_id, old.description,
        old.created_at, datetime('now'));
END;
DROP TABLE IF EXISTS deleted_iam_role_v1;

-- Add PK to deleted_iam_user. In SQLite, this requires creating a new table.
CREATE TABLE deleted_iam_user_v2(
    user_id                     CHAR(16),
    account_id                  CHAR(12),
    user_name_lower             VARCHAR(64),
    user_name_cased             VARCHAR(64),
    path                        VARCHAR(512),
    permissions_boundary_managed_policy_id CHAR(16),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6),
    CONSTRAINT pk_deleted_iam_user PRIMARY KEY (user_id)
);
INSERT OR IGNORE INTO deleted_iam_user_v2(
    user_id, account_id, user_name_lower, user_name_cased, path, permissions_boundary_managed_policy_id, created_at, deleted_at)
    SELECT user_id, account_id, user_name_lower, user_name_cased, path, permissions_boundary_managed_policy_id, created_at, deleted_at
    FROM deleted_iam_user;
ALTER TABLE deleted_iam_user RENAME TO deleted_iam_user_v1;
ALTER TABLE deleted_iam_user_v2 RENAME TO deleted_iam_user;
CREATE TRIGGER trig_delete_iam_user
AFTER DELETE ON iam_user
FOR EACH ROW
BEGIN
    INSERT INTO deleted_iam_user(
        user_id, account_id, user_name_lower, user_name_cased,
        path, permissions_boundary_managed_policy_id, created_at,
        deleted_at)
    VALUES(
        old.user_id, old.account_id, old.user_name_lower, old.user_name_cased,
        old.path, old.permissions_boundary_managed_policy_id, old.created_at,
        datetime('now'));
END;
DROP TABLE IF EXISTS deleted_iam_user_v1;

-- Add PK to deleted_managed_policy. In SQLite, this requires creating a new table.
CREATE TABLE deleted_managed_policy_v2(
    managed_policy_id           CHAR(16),
    account_id                  CHAR(12),
    managed_policy_name_lower   VARCHAR(128),
    managed_policy_name_cased   VARCHAR(128),
    path                        VARCHAR(512),
    default_version             BIGINT,
    deprecated                  BOOLEAN,
    policy_type                 VARCHAR(32),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6),
    CONSTRAINT pk_deleted_managed_policy PRIMARY KEY (managed_policy_id)
);
INSERT OR IGNORE INTO deleted_managed_policy_v2(
    managed_policy_id, account_id, managed_policy_name_lower, managed_policy_name_cased, path, default_version,
    deprecated, policy_type, created_at, deleted_at)
    SELECT managed_policy_id, account_id, managed_policy_name_lower, managed_policy_name_cased, path, default_version,
    deprecated, policy_type, created_at, deleted_at
    FROM deleted_managed_policy;
ALTER TABLE deleted_managed_policy RENAME TO deleted_managed_policy_v1;
ALTER TABLE deleted_managed_policy_v2 RENAME TO deleted_managed_policy;
CREATE TRIGGER trig_delete_managed_policy
AFTER DELETE ON managed_policy
FOR EACH ROW
BEGIN
    INSERT INTO deleted_managed_policy(
        managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated,
        policy_type, created_at, deleted_at)
    VALUES(
        old.managed_policy_id, old.account_id, old.managed_policy_name_lower,
        old.managed_policy_name_cased, old.path, old.default_version, old.deprecated,
        old.policy_type, old.created_at,
        datetime('now'));
END;
DROP TABLE IF EXISTS deleted_managed_policy_v1;

-- Add last_version to manged_policy table.
ALTER TABLE managed_policy
ADD COLUMN last_version BIGINT;

-- Add missing managed_policy_version and history table.
CREATE TABLE managed_policy_version(
    managed_policy_id           CHAR(16) NOT NULL,
    managed_policy_version      BIGINT NOT NULL,
    policy_document             TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_managed_policy_version PRIMARY KEY (managed_policy_id, managed_policy_version),
    CONSTRAINT fk_managed_policy_version_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE deleted_managed_policy_version(
    managed_policy_id           CHAR(16) NOT NULL,
    managed_policy_version      BIGINT NOT NULL,
    policy_document             TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    deleted_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_deleted_managed_policy_version PRIMARY KEY (managed_policy_id, managed_policy_version)
);

CREATE TRIGGER trig_delete_managed_policy_version
AFTER DELETE ON managed_policy_version
FOR EACH ROW
BEGIN
    INSERT INTO deleted_managed_policy_version(
        managed_policy_id, managed_policy_version, policy_document, created_at,
        deleted_at)
    VALUES(
        old.managed_policy_id, old.managed_policy_version, old.policy_document,
        old.created_at, datetime('now'));
END;