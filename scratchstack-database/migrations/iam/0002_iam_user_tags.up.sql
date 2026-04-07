-- Add iam.user_tags table
CREATE TABLE iam.user_tags (
    user_id VARCHAR(32) NOT NULL,
    key_lower VARCHAR(128) NOT NULL,
    key_cased VARCHAR(128) NOT NULL,
    value VARCHAR(256) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    updated_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_user_tags PRIMARY KEY (user_id, key_lower),
    CONSTRAINT fk_user_tags_user_id FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.user_tags IS 'Tags attached to IAM users.';
COMMENT ON COLUMN iam.user_tags.user_id IS 'Unique identifier for the user without the leading AIDA prefix.';
