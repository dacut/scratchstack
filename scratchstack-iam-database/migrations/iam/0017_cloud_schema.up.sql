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
    units VARCHAR(64) PRIMARY KEY,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE cloud.quota_units IS 'The units used for cloud quotas.';

CREATE TABLE cloud.services(
    service_id VARCHAR(32) PRIMARY KEY,
    service_dns_name VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_service_dns_name UNIQUE (service_dns_name)
);
COMMENT ON TABLE cloud.services IS 'The services available in this cloud.';

CREATE TABLE cloud.service_regions(
    service_id VARCHAR(32) NOT NULL,
    region_name VARCHAR(64) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_service_regions PRIMARY KEY (service_id, region_name),
    CONSTRAINT fk_service FOREIGN KEY (service_id) REFERENCES cloud.services(service_id),
    CONSTRAINT fk_region FOREIGN KEY (region_name) REFERENCES cloud.regions(region_name)
);
COMMENT ON TABLE cloud.service_regions IS 'Mapping of services to the regions they are available in.';

CREATE TABLE cloud.regional_quota_definitions(
    regional_quota_id VARCHAR(64) PRIMARY KEY,
    service_id VARCHAR(32) NOT NULL,
    quota_name VARCHAR(64) NOT NULL,
    description TEXT,
    default_value NUMERIC,
    units VARCHAR(64) NOT NULL,
    min_value NUMERIC,
    max_value NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_service FOREIGN KEY (service_id) REFERENCES cloud.services(service_id),
    CONSTRAINT fk_units FOREIGN KEY (units) REFERENCES cloud.quota_units(units)
); 
COMMENT ON TABLE cloud.regional_quota_definitions IS 'Definitions of regional quotas for cloud services.';

CREATE TABLE cloud.global_quota_definitions(
    global_quota_id VARCHAR(64) PRIMARY KEY,
    service_id VARCHAR(32) NOT NULL,
    quota_name VARCHAR(64) NOT NULL,
    description TEXT,
    default_value NUMERIC,
    units VARCHAR(64) NOT NULL,
    min_value NUMERIC,
    max_value NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_service FOREIGN KEY (service_id) REFERENCES cloud.services(service_id),
    CONSTRAINT fk_units FOREIGN KEY (units) REFERENCES cloud.quota_units(units)
);
COMMENT ON TABLE cloud.global_quota_definitions IS 'Definitions of global quotas for cloud services.';

CREATE TABLE cloud.account_regional_quotas(
    account_id CHAR(12) NOT NULL,
    region_name VARCHAR(64) NOT NULL,
    regional_quota_id VARCHAR(64) NOT NULL,
    quota_value NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_account_regional_quotas PRIMARY KEY (account_id, region_name, regional_quota_id),
    CONSTRAINT fk_region FOREIGN KEY (region_name) REFERENCES cloud.regions(region_name),
    CONSTRAINT fk_regional_quota FOREIGN KEY (regional_quota_id) REFERENCES cloud.regional_quota_definitions(regional_quota_id)
);
COMMENT ON TABLE cloud.account_regional_quotas IS 'Regional quotas assigned to cloud accounts.';

CREATE TABLE cloud.account_global_quotas(
    account_id CHAR(12) NOT NULL,
    global_quota_id VARCHAR(64) NOT NULL,
    quota_value NUMERIC,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_account_global_quotas PRIMARY KEY (account_id, global_quota_id),
    CONSTRAINT fk_global_quota FOREIGN KEY (global_quota_id) REFERENCES cloud.global_quota_definitions(global_quota_id)
);
COMMENT ON TABLE cloud.account_global_quotas IS 'Global quotas assigned to cloud accounts.';

INSERT INTO cloud.quota_units(units)
VALUES
    ('boolean'),
    ('fraction'),
    ('bytes'),
    ('seconds'),
    ('requests'),
    ('requests/second');