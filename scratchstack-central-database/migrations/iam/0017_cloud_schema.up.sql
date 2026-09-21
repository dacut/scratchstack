CREATE SCHEMA cloud;
COMMENT ON SCHEMA cloud IS 'Global cloud domain tables containing partition information, defined services, and quotas.';

ALTER TABLE iam.partition SET SCHEMA cloud;

CREATE TABLE cloud.regions(
    region_name VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE cloud.regions IS 'The regions available in this cloud.';

CREATE TABLE cloud.quota_units(
    unit VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE cloud.quota_units IS 'The units used for cloud quotas.';

CREATE TABLE cloud.services(
    service_id VARCHAR(32) PRIMARY KEY,
    service_dns_name VARCHAR(256) NOT NULL UNIQUE,
    description TEXT,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE cloud.services IS 'The services available in this cloud.';

CREATE TABLE cloud.service_regions(
    service_id VARCHAR(32) NOT NULL,
    region_name VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (service_id, region_name),
    FOREIGN KEY (service_id) REFERENCES cloud.services(service_id),
    FOREIGN KEY (region_name) REFERENCES cloud.regions(region_name)
);
COMMENT ON TABLE cloud.service_regions IS 'Mapping of services to the regions they are available in.';

CREATE TABLE cloud.quota_definitions(
    quota_id VARCHAR(64) PRIMARY KEY,
    service_id VARCHAR(32) NOT NULL,
    quota_name VARCHAR(64) NOT NULL,
    global BOOLEAN NOT NULL,
    description TEXT,
    default_value NUMERIC,
    unit VARCHAR(64) NOT NULL,
    min_value NUMERIC,
    max_value NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CHECK (
        (min_value IS NULL OR max_value IS NULL OR min_value <= max_value) AND
        (default_value IS NULL OR min_value IS NULL OR default_value >= min_value) AND
        (default_value IS NULL OR max_value IS NULL OR default_value <= max_value)
    ),
    UNIQUE (service_id, quota_name),
    UNIQUE (service_id, quota_id),
    FOREIGN KEY (service_id) REFERENCES cloud.services(service_id),
    FOREIGN KEY (unit) REFERENCES cloud.quota_units(unit)
);
COMMENT ON TABLE cloud.quota_definitions IS 'Definitions of quotas for cloud services.';

CREATE TABLE cloud.account_quotas(
    account_id CHAR(12) NOT NULL,
    service_id VARCHAR(32) NOT NULL,
    quota_id VARCHAR(64) NOT NULL,
    region_name VARCHAR(64),
    quota_value NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    -- A global quota leaves region_name NULL, so this cannot be a primary key: PostgreSQL makes
    -- every primary key column NOT NULL, which would leave global quotas nowhere to go. NULLS NOT
    -- DISTINCT gives the same uniqueness a primary key would, and treats the NULL of a global
    -- quota as a value, so an account gets one global row per quota rather than any number of
    -- them.
    UNIQUE NULLS NOT DISTINCT (account_id, quota_id, region_name),
    -- service_id is carried so these two keys can be composite. Referencing the region and the
    -- quota definition independently would let a quota be assigned in a region its service is not
    -- available in; together they cannot disagree about which service is being talked about.
    -- A global quota leaves region_name NULL, and a composite foreign key with a NULL in it is
    -- satisfied without being checked (MATCH SIMPLE, the default) -- there is no region for it to
    -- be wrong about.
    FOREIGN KEY (service_id, region_name)
        REFERENCES cloud.service_regions(service_id, region_name),
    FOREIGN KEY (service_id, quota_id)
        REFERENCES cloud.quota_definitions(service_id, quota_id)
);
COMMENT ON TABLE cloud.account_quotas IS 'Quotas assigned to cloud accounts.';

INSERT INTO cloud.quota_units(unit)
VALUES
    ('boolean'),
    ('fraction'),
    ('bytes'),
    ('seconds'),
    ('requests'),
    ('requests/second');