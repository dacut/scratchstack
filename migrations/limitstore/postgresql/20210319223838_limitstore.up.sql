-- Create the limitstore schema and tables
CREATE SCHEMA limitstore;

CREATE TABLE limitstore.value_type(
    value_type                  VARCHAR(16) NOT NULL,
    CONSTRAINT pk_value_type PRIMARY KEY (value_type)
);
INSERT INTO limitstore.value_type(value_type) VALUES('INTEGER'), ('STRING');

CREATE TABLE limitstore.region(
    region                      VARCHAR(64) NOT NULL,
    CONSTRAINT pk_region PRIMARY KEY (region)
);
INSERT INTO limitstore.region(region) VALUES('global'), ('local');

CREATE TABLE limitstore.limit_definition(
    limit_id                    BIGINT NOT NULL,
    service_name                VARCHAR(64) NOT NULL,
    limit_name                  VARCHAR(64) NOT NULL,
    description                 TEXT,
    value_type                  VARCHAR(16) NOT NULL,
    default_int_value           INTEGER,
    default_string_value        VARCHAR(1024),
    min_value                   INTEGER,
    max_value                   INTEGER,
    CONSTRAINT pk_limit_definition PRIMARY KEY (limit_id),
    CONSTRAINT uk_limit_definition_service_name_limit_name
    UNIQUE (service_name, limit_name),
    CONSTRAINT fk_limit_definition_value_type
    FOREIGN KEY (value_type) REFERENCES limitstore.value_type(value_type)
);
CREATE SEQUENCE limitstore.seq_limit_id MINVALUE 1 START WITH 1
OWNED BY limitstore.limit_definition.limit_id;

CREATE TABLE limitstore.account_limit(
    account_id                  CHAR(12) NOT NULL,
    limit_id                    BIGINT NOT NULL,
    region                      VARCHAR(64) NOT NULL,
    int_value                   INTEGER,
    string_value                VARCHAR(1024),
    CONSTRAINT pk_account_limit PRIMARY KEY (account_id,limit_id,region),
    CONSTRAINT fk_account_limit_limit_id
    FOREIGN KEY (limit_id) REFERENCES limitstore.limit_definition(limit_id),
    CONSTRAINT fk_account_limit_region
    FOREIGN KEY (region) REFERENCES limitstore.region(region)
);
