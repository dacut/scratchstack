ALTER TABLE iam.role_session_token_keys RENAME TO session_token_encryption_keys;
ALTER TABLE iam.session_token_encryption_keys
RENAME COLUMN role_session_token_key_id TO session_token_encryption_key_id;
ALTER TABLE iam.session_token_encryption_keys
RENAME COLUMN valid_from TO issue_valid_from;
ALTER TABLE iam.session_token_encryption_keys
RENAME COLUMN expires_at TO issue_expires_at;
ALTER TABLE iam.session_token_encryption_keys
ADD COLUMN accept_expires_at TIMESTAMP WITH TIME ZONE;
ALTER TABLE iam.session_token_encryption_keys
ADD CONSTRAINT stek_encryption_algorithm_check CHECK (encryption_algorithm IN ('AES256-GCM'));
