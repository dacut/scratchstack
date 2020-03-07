-- Schema version 20200306-01
-- Limitstore and IAM tables.

CREATE SCHEMA limitstore;
SET SCHEMA 'limitstore';

CREATE TABLE value_type(
    value_type                  VARCHAR(16) PRIMARY KEY
);
INSERT INTO value_type(value_type) VALUES('INTEGER'), ('STRING');

CREATE TABLE region(
    region                      VARCHAR(64) PRIMARY KEY
);
INSERT INTO region(region) VALUES('local');

CREATE TABLE limit_definition(
    limit_id                    BIGINT PRIMARY KEY NOT NULL,
    service                     VARCHAR(32) NOT NULL,
    description                 TEXT,
    value_type                  VARCHAR(16) NOT NULL,
    default_int_value           INTEGER,
    default_string_value        VARCHAR(1024),
    min_value                   INTEGER,
    max_value                   INTEGER,
    CONSTRAINT fk_limit_definition_value_type
    FOREIGN KEY (value_type) REFERENCES value_type(value_type)
);

CREATE TABLE account_limit(
    account_id                  CHAR(12) NOT NULL,
    limit_id                    BIGINT NOT NULL,
    region                      VARCHAR(64) NOT NULL,
    int_value                   INTEGER,
    string_value                VARCHAR(1024),
    CONSTRAINT pk_account_limit
    PRIMARY KEY (account_id,limit_id,region),
    CONSTRAINT fk_account_limit_limit_id
    FOREIGN KEY (limit_id) REFERENCES limit_definition(limit_id),
    CONSTRAINT fk_account_limit_region
    FOREIGN KEY (region) REFERENCES region(region)
);


CREATE SCHEMA iam;
SET SCHEMA 'iam';

CREATE TABLE account(
    account_id                  CHAR(12) PRIMARY KEY NOT NULL,
    email                       VARCHAR(256) NOT NULL,
    active                      BOOLEAN NOT NULL,
    alias                       VARCHAR(63),
    CONSTRAINT uk_account_email UNIQUE (email),
    CONSTRAINT uk_account_alias UNIQUE (alias)
);
INSERT INTO account(account_id, email, active, alias)
VALUES('000000000000', 'aws', TRUE, 'aws');

CREATE TABLE managed_policy(
    managed_policy_id           CHAR(17) PRIMARY KEY NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    managed_policy_name_lower   VARCHAR(128) NOT NULL,
    managed_policy_name_cased   VARCHAR(128) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    default_version             BIGINT,
    deprecated                  BOOLEAN NOT NULL,
    CONSTRAINT fk_managed_policy_account_id
    FOREIGN KEY (account_id) REFERENCES account(account_id),
    CONSTRAINT uk_managed_policy_account_id_managed_policy_name_lower
    UNIQUE (account_id, managed_policy_name_lower)
);

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

CREATE TABLE deleted_managed_policy(
    managed_policy_id           CHAR(17) PRIMARY KEY NOT NULL,
    account_id                  CHAR(12) NOT NULL,
    managed_policy_name_lower   VARCHAR(128) NOT NULL,
    managed_policy_name_cased   VARCHAR(128) NOT NULL,
    path                        VARCHAR(512) NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    deleted_at                  TIMESTAMP(6) NOT NULL
);

CREATE FUNCTION on_delete_managed_policy() RETURNS TRIGGER AS $body$
BEGIN
    INSERT INTO deleted_managed_policy(
        managed_policy_id, account_id, managed_policy_name_lower,
        managed_policy_name_cased, path, created_at, deleted_at)
    VALUES(
        old.managed_policy_id, old.account_id, old.managed_policy_name_lower,
        old.managed_policy_name_cased, old.path, old.created_at,
        CURRENT_TIMESTAMP AT TIME ZONE 'UTC');
    RETURN old;
END
$body$ LANGUAGE plpgsql;

CREATE TRIGGER trig_delete_managed_policy
AFTER DELETE ON managed_policy
FOR EACH ROW
EXECUTE FUNCTION on_delete_managed_policy();

CREATE TABLE deleted_managed_policy_version(
    managed_policy_id           CHAR(17) NOT NULL,
    managed_policy_version      BIGINT NOT NULL,
    policy_document             TEXT NOT NULL,
    created_at                  TIMESTAMP(6) NOT NULL,
    deleted_at                  TIMESTAMP(6) NOT NULL,
    CONSTRAINT pk_deleted_managed_policy_version
    PRIMARY KEY (managed_policy_id, managed_policy_version)
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

UPDATE ss_schema.schema SET version='20200306-01';
