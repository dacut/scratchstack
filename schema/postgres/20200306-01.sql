-- Schema version 20200306-01
-- Limitstore and IAM tables.

CREATE SCHEMA limitstore;
SET SCHEMA 'limitstore';

CREATE TABLE value_type(
    value_type                  VARCHAR(16) NOT NULL,
    CONSTRAINT pk_value_type PRIMARY KEY (value_type)
);
INSERT INTO value_type(value_type) VALUES('INTEGER'), ('STRING');

CREATE TABLE region(
    region                      VARCHAR(64) NOT NULL,
    CONSTRAINT pk_region PRIMARY KEY (region)
);
INSERT INTO region(region) VALUES('local');

CREATE TABLE limit_definition(
    limit_id                    BIGINT NOT NULL,
    service_name                VARCHAR(64) NOT NULL,
    description                 TEXT,
    value_type                  VARCHAR(16) NOT NULL,
    default_int_value           INTEGER,
    default_string_value        VARCHAR(1024),
    min_value                   INTEGER,
    max_value                   INTEGER,
    CONSTRAINT pk_limit_definition PRIMARY KEY (limit_id),
    CONSTRAINT fk_limit_definition_value_type
    FOREIGN KEY (value_type) REFERENCES value_type(value_type)
);

CREATE TABLE account_limit(
    account_id                  CHAR(12) NOT NULL,
    limit_id                    BIGINT NOT NULL,
    region                      VARCHAR(64) NOT NULL,
    int_value                   INTEGER,
    string_value                VARCHAR(1024),
    CONSTRAINT pk_account_limit PRIMARY KEY (account_id,limit_id,region),
    CONSTRAINT fk_account_limit_limit_id
    FOREIGN KEY (limit_id) REFERENCES limit_definition(limit_id),
    CONSTRAINT fk_account_limit_region
    FOREIGN KEY (region) REFERENCES region(region)
);


CREATE SCHEMA iam;
SET SCHEMA 'iam';

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
    managed_policy_id           CHAR(17) NOT NULL,
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
    managed_policy_id           CHAR(17),
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

CREATE FUNCTION on_delete_managed_policy() RETURNS TRIGGER AS $body$
BEGIN
    INSERT INTO deleted_managed_policy(
        managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, default_version, deprecated,
        policy_type, created_at, deleted_at)
    VALUES(
        old.managed_policy_id, old.account_id, old.managed_policy_name_lower,
        old.managed_policy_name_cased, old.path, old.default_version, old.deprecated,
        old.policy_type, old.created_at,
        CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    RETURN old;
END
$body$ LANGUAGE plpgsql;

CREATE TRIGGER trig_delete_managed_policy
AFTER DELETE ON managed_policy
FOR EACH ROW
EXECUTE FUNCTION on_delete_managed_policy();

CREATE TABLE managed_policy_version(
    managed_policy_id           CHAR(17) NOT NULL,
    managed_policy_version      BIGINT NOT NULL,
    policy_document             TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_managed_policy_version
    PRIMARY KEY (managed_policy_id, managed_policy_version),
    CONSTRAINT fk_managed_policy_version_managed_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE deleted_managed_policy_version(
    managed_policy_id           CHAR(17),
    managed_policy_version      BIGINT,
    policy_document             TEXT,
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6)
);

CREATE FUNCTION on_delete_managed_policy_version() RETURNS TRIGGER AS $body$
BEGIN
    INSERT INTO deleted_managed_policy_version(
        managed_policy_id, managed_policy_version, policy_document,
        created_at, deleted_at)
    VALUES(
        old.managed_policy_id, old.managed_policy_version, old.policy_document,
        old.created_at,
        CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    RETURN old;
END
$body$ LANGUAGE plpgsql;

CREATE TRIGGER trig_delete_managed_policy_version
AFTER DELETE ON managed_policy_version
FOR EACH ROW
EXECUTE FUNCTION on_delete_managed_policy_version();

CREATE TABLE iam_user(
    user_id                     CHAR(17) NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    user_name_lower             VARCHAR(64) NOT NULL,
    user_name_cased             VARCHAR(64) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    permissions_boundary_managed_policy_id CHAR(17),
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user PRIMARY KEY (user_id),
    CONSTRAINT uk_iam_user_account_id_user_name_lower
    UNIQUE (account_id, user_name_lower),
    CONSTRAINT uk_iam_user_permissions_boundary_managed_policy_id
    FOREIGN KEY (permissions_boundary_managed_policy_id)
    REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE deleted_iam_user(
    user_id                     CHAR(17),
    account_id                  CHAR(12),
    user_name_lower             VARCHAR(64),
    user_name_cased             VARCHAR(64),
    path                        VARCHAR(512),
    permissions_boundary_managed_policy_id CHAR(17),
    created_at                  TIMESTAMP(6),
    deleted_at                  TIMESTAMP(6)
);

CREATE FUNCTION on_delete_iam_user() RETURNS TRIGGER AS $body$
BEGIN
    INSERT INTO deleted_iam_user(
        user_id, account_id, user_name_lower, user_name_cased,
        path, permissions_boundary_managed_policy_id, created_at,
        deleted_at)
    VALUES(
        old.user_id, old.account_id, old.user_name_lower, old.user_name_cased,
        old.path, old.permissions_boundary_managed_policy_id, old.created_at,
        CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    RETURN old;
END
$body$ LANGUAGE plpgsql;

CREATE TRIGGER trig_delete_iam_user
AFTER DELETE ON iam_user
FOR EACH ROW
EXECUTE FUNCTION on_delete_iam_user();

CREATE TABLE iam_user_attached_policy(
    user_id                     CHAR(17) NOT NULL,
    managed_policy_id           CHAR(17) NOT NULL,
    CONSTRAINT pk_iam_user_attached_policy PRIMARY KEY (user_id, managed_policy_id),
    CONSTRAINT fk_iam_user_attached_policy_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id),
    CONSTRAINT fk_iam_user_attached_policy_managed_policy_id
    FOREIGN KEY (managed_policy_id) REFERENCES managed_policy(managed_policy_id)
);

CREATE TABLE iam_user_inline_policy(
    user_id                     CHAR(17) NOT NULL,
    policy_name_lower           VARCHAR(128) NOT NULL,
    policy_name_cased           VARCHAR(128) NOT NULL,
    policy_document             TEXT NOT NULL,
    CONSTRAINT pk_user_inline_policy PRIMARY KEY (user_id, policy_name_lower),
    CONSTRAINT fk_user_inline_policy_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_login_profile(
    user_id                     CHAR(17) NOT NULL,
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
    user_id                     CHAR(17) NOT NULL,
    password_hash_algorithm     VARCHAR(32) NOT NULL,
    password_hash               VARCHAR(256) NOT NULL,
    password_changed_at         TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_password_history
    PRIMARY KEY (user_id, password_changed_at),
    CONSTRAINT fk_iam_user_password_history_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_credential(
    user_id                     CHAR(17) NOT NULL,
    access_key_id               CHAR(17) NOT NULL,
    secret_key                  VARCHAR(256) NOT NULL,
    active                      BOOLEAN NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_credential PRIMARY KEY (user_id, access_key_id),
    CONSTRAINT fk_iam_user_credential_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_ssh_public_key(
    user_id                     CHAR(17) NOT NULL,
    public_key_id               CHAR(17) NOT NULL,
    fingerprint                 CHAR(47) NOT NULL,
    ssh_public_key_body         TEXT NOT NULL,
    active                      BOOLEAN NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_ssh_public_key PRIMARY KEY (user_id, public_key_id),
    CONSTRAINT fk_iam_user_ssh_public_key_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

CREATE TABLE iam_user_service_specific_credential(
    user_id                     CHAR(17) NOT NULL,
    service_specific_credential_id CHAR(17) NOT NULL,
    service_name                VARCHAR(64) NOT NULL,
    service_password            VARCHAR(64) NOT NULL,
    active                      BOOLEAN NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_iam_user_service_specific_credential PRIMARY KEY (user_id, service_specific_credential_id),
    CONSTRAINT fk_iam_user_service_specific_credential_user_id
    FOREIGN KEY (user_id) REFERENCES iam_user(user_id)
);

UPDATE ss_schema.schema SET version='20200306-01';
