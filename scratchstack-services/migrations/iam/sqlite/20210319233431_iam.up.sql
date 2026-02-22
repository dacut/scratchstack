-- Create IAM schema and tables
CREATE TABLE account(
    account_id                  CHAR(12) NOT NULL,
    email                       VARCHAR(256) NOT NULL,
    active                      BOOLEAN NOT NULL,
    alias                       VARCHAR(63),
    CONSTRAINT pk_account PRIMARY KEY (account_id),
    CONSTRAINT uk_account_email UNIQUE (email),
    CONSTRAINT uk_account_alias UNIQUE (alias)
);
INSERT INTO account(account_id, email, active, alias)
VALUES('000000000000', 'aws', TRUE, 'aws');

CREATE TABLE managed_policy(
    managed_policy_id           CHAR(16) NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    managed_policy_name_lower   VARCHAR(128) NOT NULL,
    managed_policy_name_cased   VARCHAR(128) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    default_version             BIGINT,
    deprecated                  BOOLEAN NOT NULL,
    policy_type                 VARCHAR(32),
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_managed_policy PRIMARY KEY (managed_policy_id),
    CONSTRAINT fk_managed_policy_account_id
    FOREIGN KEY (account_id) REFERENCES account(account_id),
    CONSTRAINT uk_managed_policy_account_id_managed_policy_name_lower
    UNIQUE (account_id, managed_policy_name_lower)
);

CREATE TABLE deleted_managed_policy(
    managed_policy_id           CHAR(16),
    account_id                  CHAR(12),
    managed_policy_name_lower   VARCHAR(128),
    managed_policy_name_cased   VARCHAR(128),
    path                        VARCHAR(512),
    default_version             BIGINT,
    deprecated                  BOOLEAN,
    policy_type                 VARCHAR(32),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6)
);

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

CREATE TABLE iam_user(
    user_id                     CHAR(16) NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    user_name_lower             VARCHAR(64) NOT NULL,
    user_name_cased             VARCHAR(64) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    permissions_boundary_managed_policy_id CHAR(16),
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user PRIMARY KEY (user_id),
    CONSTRAINT uk_iam_user_account_id_user_name_lower
    UNIQUE (account_id, user_name_lower),
    CONSTRAINT uk_iam_user_permissions_boundary_managed_policy_id
    FOREIGN KEY (permissions_boundary_managed_policy_id)
    REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE deleted_iam_user(
    user_id                     CHAR(16),
    account_id                  CHAR(12),
    user_name_lower             VARCHAR(64),
    user_name_cased             VARCHAR(64),
    path                        VARCHAR(512),
    permissions_boundary_managed_policy_id CHAR(16),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6)
);

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

CREATE TABLE iam_user_attached_policy(
    user_id                     CHAR(16) NOT NULL,
    managed_policy_id           CHAR(16) NOT NULL,
    CONSTRAINT pk_iam_user_attached_policy PRIMARY KEY (user_id, managed_policy_id),
    CONSTRAINT fk_iam_user_attached_policy_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id),
    CONSTRAINT fk_iam_user_attached_policy_managed_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE iam_user_inline_policy(
    user_id                     CHAR(16) NOT NULL,
    policy_name_lower           VARCHAR(128) NOT NULL,
    policy_name_cased           VARCHAR(128) NOT NULL,
    policy_document             TEXT NOT NULL,
    CONSTRAINT pk_iam_user_inline_policy PRIMARY KEY (user_id, policy_name_lower),
    CONSTRAINT fk_iam_user_inline_policy_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_login_profile(
    user_id                     CHAR(16) NOT NULL,
    password_hash_algorithm     VARCHAR(32) NOT NULL,
    password_hash               VARCHAR(256) NOT NULL,
    password_reset_required     BOOLEAN NOT NULL,
    password_last_changed_at    TIMESTAMP(6) NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    last_used_at                TIMESTAMP(6),
    CONSTRAINT pk_iam_user_login_profile PRIMARY KEY (user_id),
    CONSTRAINT fk_iam_user_login_profile_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_password_history(
    user_id                     CHAR(16) NOT NULL,
    password_hash_algorithm     VARCHAR(32) NOT NULL,
    password_hash               VARCHAR(256) NOT NULL,
    password_changed_at         TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_password_history
    PRIMARY KEY (user_id, password_changed_at),
    CONSTRAINT fk_iam_user_password_history_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_credential(
    user_id                     CHAR(16) NOT NULL,
    access_key_id               CHAR(16) NOT NULL,
    secret_key                  VARCHAR(256) NOT NULL,
    active                      BOOLEAN NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_credential PRIMARY KEY (user_id, access_key_id),
    CONSTRAINT fk_iam_user_credential_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_ssh_public_key(
    user_id                     CHAR(16) NOT NULL,
    public_key_id               CHAR(16) NOT NULL,
    fingerprint                 CHAR(47) NOT NULL,
    ssh_public_key_body         TEXT NOT NULL,
    active                      BOOLEAN NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_ssh_public_key PRIMARY KEY (user_id, public_key_id),
    CONSTRAINT fk_iam_user_ssh_public_key_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_service_specific_credential(
    user_id                     CHAR(16) NOT NULL,
    service_specific_credential_id CHAR(16) NOT NULL,
    service_name                VARCHAR(64) NOT NULL,
    service_password            VARCHAR(64) NOT NULL,
    active                      BOOLEAN NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_service_specific_credential PRIMARY KEY (user_id, service_specific_credential_id),
    CONSTRAINT fk_iam_user_service_specific_credential_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_group(
    group_id                    CHAR(16) NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    group_name_lower            VARCHAR(64) NOT NULL,
    group_name_cased            VARCHAR(64) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_group PRIMARY KEY (group_id),
    CONSTRAINT uk_iam_group_account_id_group_name_lower
    UNIQUE (account_id, group_name_lower)
);

CREATE TABLE deleted_iam_group(
    group_id                    CHAR(16),
    account_id                  CHAR(12),
    group_name_lower            VARCHAR(64),
    group_name_cased            VARCHAR(64),
    path                        VARCHAR(512),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6)
);

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

CREATE TABLE iam_group_attached_policy(
    group_id                    CHAR(16) NOT NULL,
    managed_policy_id           CHAR(16) NOT NULL,
    CONSTRAINT pk_iam_group_attached_policy PRIMARY KEY (group_id, managed_policy_id),
    CONSTRAINT fk_iam_group_attached_policy_group_id
    FOREIGN KEY (group_id) REFERENCES iam_group(group_id),
    CONSTRAINT fk_iam_group_attached_policy_managed_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE iam_group_inline_policy(
    group_id                    CHAR(16) NOT NULL,
    policy_name_lower           VARCHAR(128) NOT NULL,
    policy_name_cased           VARCHAR(128) NOT NULL,
    policy_document             TEXT NOT NULL,
    CONSTRAINT pk_iam_group_inline_policy PRIMARY KEY (group_id, policy_name_lower),
    CONSTRAINT fk_iam_group_inline_policy_group_id
    FOREIGN KEY (group_id) REFERENCES iam_group(group_id)
);

CREATE TABLE iam_group_member(
    group_id                    CHAR(16) NOT NULL,
    user_id                     CHAR(16) NOT NULL,
    CONSTRAINT pk_iam_group_member PRIMARY KEY (group_id, user_id),
    CONSTRAINT fk_iam_group_member_group_id
    FOREIGN KEY (group_id) REFERENCES iam_group(group_id),
    CONSTRAINT fk_iam_group_member_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_role(
    role_id                     CHAR(16) NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    role_name_lower             VARCHAR(64) NOT NULL,
    role_name_cased             VARCHAR(64) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    permissions_boundary_managed_policy_id CHAR(16),
    description                 VARCHAR(1000),
    assume_role_policy_document TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_role PRIMARY KEY(role_id),
    CONSTRAINT uk_iam_role_account_id_role_name_lower
    UNIQUE (account_id, role_name_lower)
);

CREATE TABLE deleted_iam_role(
    role_id                     CHAR(16),
    account_id                  CHAR(12),
    role_name_lower             VARCHAR(64),
    role_name_cased             VARCHAR(64),
    path                        VARCHAR(512),
    permissions_boundary_managed_policy_id CHAR(16),
    description                 VARCHAR(1000),
    assume_role_policy_document TEXT,
    created_at                  TIMESTAMP(6)
);

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

CREATE TABLE iam_role_attached_policy(
    role_id                     CHAR(16) NOT NULL,
    managed_policy_id           CHAR(16) NOT NULL,
    CONSTRAINT pk_iam_role_attached_policy PRIMARY KEY (role_id, managed_policy_id),
    CONSTRAINT fk_iam_role_attached_policy_role_id
    FOREIGN KEY (role_id) REFERENCES iam_role(role_id),
    CONSTRAINT fk_iam_role_attached_policy_managed_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE iam_role_inline_policy(
    role_id                     CHAR(16) NOT NULL,
    policy_name_lower           VARCHAR(128) NOT NULL,
    policy_name_cased           VARCHAR(128) NOT NULL,
    policy_document             TEXT NOT NULL,
    CONSTRAINT pk_iam_role_inline_policy PRIMARY KEY (role_id, policy_name_lower),
    CONSTRAINT fk_iam_role_inline_policy_role_id
    FOREIGN KEY (role_id) REFERENCES iam_role(role_id)
);

CREATE TABLE iam_role_token_key(
    access_key_id               CHAR(16) NOT NULL,
    encryption_algorithm        VARCHAR(16) NOT NULL,
    encryption_key              BYTEA NOT NULL,
    valid_at                    TIMESTAMP(6) NOT NULL,
    expires_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_role_token_key PRIMARY KEY (access_key_id)
);
