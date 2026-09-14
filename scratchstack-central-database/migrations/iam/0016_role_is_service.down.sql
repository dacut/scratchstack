--- Remove the is_service column from iam.roles.
ALTER TABLE iam.roles
DROP COLUMN is_service;
