DROP TABLE IF EXISTS iam.role_tags;
ALTER TABLE iam.roles DROP CONSTRAINT IF EXISTS ck_irole_max_session_duration;
ALTER TABLE iam.roles DROP COLUMN IF EXISTS max_session_duration;
