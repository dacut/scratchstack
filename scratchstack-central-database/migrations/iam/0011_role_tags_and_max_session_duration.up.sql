-- Add max_session_duration column to iam.roles and create the iam.role_tags table.
ALTER TABLE iam.roles ADD COLUMN max_session_duration INTEGER;
COMMENT ON COLUMN iam.roles.max_session_duration IS 'Maximum session duration (in seconds) for the role. Must be between 3600 and 43200.';
ALTER TABLE iam.roles ADD CONSTRAINT ck_irole_max_session_duration
    CHECK (max_session_duration IS NULL OR (max_session_duration >= 3600 AND max_session_duration <= 43200));

CREATE TABLE iam.role_tags (
    role_id VARCHAR(32) NOT NULL,
    key_lower VARCHAR(128) NOT NULL,
    key_cased VARCHAR(128) NOT NULL,
    value VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_role_tags PRIMARY KEY (role_id, key_lower),
    CONSTRAINT fk_role_tags_role_id FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.role_tags IS 'Tags attached to IAM roles.';
COMMENT ON COLUMN iam.role_tags.role_id IS 'Unique identifier for the role without the leading AROA prefix.';
