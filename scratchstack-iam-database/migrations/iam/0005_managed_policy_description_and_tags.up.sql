-- Add description column to managed_policies and create managed_policy_tags table
ALTER TABLE iam.managed_policies ADD COLUMN description VARCHAR(1000);
COMMENT ON COLUMN iam.managed_policies.description IS 'A friendly description of the managed policy.';

CREATE TABLE iam.managed_policy_tags (
    managed_policy_id VARCHAR(32) NOT NULL,
    key_lower VARCHAR(128) NOT NULL,
    key_cased VARCHAR(128) NOT NULL,
    value VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_managed_policy_tags PRIMARY KEY (managed_policy_id, key_lower),
    CONSTRAINT fk_managed_policy_tags_mp_id FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.managed_policy_tags IS 'Tags attached to IAM managed policies.';
COMMENT ON COLUMN iam.managed_policy_tags.managed_policy_id IS 'Managed policy id without the leading ANPA prefix.';
