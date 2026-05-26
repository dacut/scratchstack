INSERT INTO iam.accounts(account_id, email, alias) VALUES
('123456789012', 'example1@example.com', 'example-account-1'),
('210987654321', 'example2@example.com', 'example-account-2');

INSERT INTO iam.password_hash_algorithms(password_hash_algorithm_id, algorithm_name, parameters) VALUES
('Argon2-2025', 'Argon2', '{"parallelism": 1, "memory": 19456, "iterations": 4}');

INSERT INTO iam.managed_policies(managed_policy_id, account_id, managed_policy_name_lower, managed_policy_name_cased, path, default_version, deprecated, latest_version) VALUES
('AAAABBBBCCCCDDDD', '123456789012', 'example-managed-policy-1', 'Example-Managed-Policy-1', '/', 1, false, 1);

INSERT INTO iam.managed_policy_versions(managed_policy_id, managed_policy_version, policy_document) VALUES
('AAAABBBBCCCCDDDD', 1, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:ListBucket","Resource":"*"}]}');

INSERT INTO iam.users(user_id, account_id, user_name_lower, user_name_cased, path, permissions_boundary_managed_policy_id) VALUES
('EXAMPLEUSERID123', '123456789012', 'example-user-1', 'Example-User-1', '/', 'AAAABBBBCCCCDDDD'),
('EXAMPLEUSERID456', '210987654321', 'example-user-2', 'Example-User-2', '/a/b/c/', NULL);

INSERT INTO iam.user_attached_policies(user_id, managed_policy_id) VALUES
('EXAMPLEUSERID456', 'AAAABBBBCCCCDDDD');

INSERT INTO iam.user_inline_policies(user_id, policy_name_lower, policy_name_cased, policy_document) VALUES
('EXAMPLEUSERID456', 'example-inline-policy-1', 'Example-Inline-Policy-1', '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:*","Resource":"*"}]}');

INSERT INTO iam.user_credentials(access_key_id, user_id, secret_key, enabled) VALUES
('EXAMPLEACCESSKEYID123', 'EXAMPLEUSERID123', 'examplesecretaccesskey', TRUE);

INSERT INTO iam.user_login_profiles(user_id, password_hash_algorithm_id, password_hash, password_reset_required, password_last_changed_at) VALUES
('EXAMPLEUSERID123', 'Argon2-2025', 'examplehashvalue', FALSE, '2024-01-01T00:00:00Z');

INSERT INTO iam.user_password_history(user_id, password_hash_algorithm, password_hash, password_created_at, password_changed_at) VALUES
('EXAMPLEUSERID123', 'Argon2-2025', 'oldexamplehashvalue', '2023-11-01T00:00:00Z', '2023-12-01T00:00:00Z');

INSERT INTO iam.user_service_specific_credentials(service_specific_credential_id, user_id, service_name, service_user_name, service_password, expires_at, enabled) VALUES
('EXAMPLESERVICECREDENTIALID123', 'EXAMPLEUSERID123', 'example-service', 'example-at-123456789012', 'exampleservicepassword', '2024-12-31T23:59:59Z', TRUE);

INSERT INTO iam.user_ssh_public_keys(ssh_public_key_id, user_id, fingerprint, ssh_public_key_body, enabled) VALUES
('EXAMPLESSHPUBLICKEYID123', 'EXAMPLEUSERID123', '1d:b2:bd:a3:e5:96:99:eb:9a:38:59:dc:53:69:7d:6a', 'ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFki4uuVgDirq4l+jDmJ8shLIBG7minPPZpBV7M/UZpM example@example.com', TRUE);

INSERT INTO iam.groups(group_id, account_id, group_name_lower, group_name_cased, path) VALUES
('EXAMPLEGROUPID123', '123456789012', 'example-group-1', 'Example-Group-1', '/');

INSERT INTO iam.group_attached_policies(group_id, managed_policy_id) VALUES
('EXAMPLEGROUPID123', 'AAAABBBBCCCCDDDD');

INSERT INTO iam.group_inline_policies(group_id, policy_name_lower, policy_name_cased, policy_document) VALUES
('EXAMPLEGROUPID123', 'example-group-inline-policy-1', 'Example-Group-Inline-Policy-1', '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"dynamodb:*","Resource":"*"}]}');

INSERT INTO iam.group_memberships(group_id, user_id) VALUES
('EXAMPLEGROUPID123', 'EXAMPLEUSERID123');

INSERT INTO iam.roles(role_id, account_id, role_name_lower, role_name_cased, path, permissions_boundary_managed_policy_id, assume_role_policy_document) VALUES
('EXAMPLEROLEID123', '123456789012', 'example-role-1', 'Example-Role-1', '/', NULL, '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"Service":"lambda.amazonaws.com"},"Action":"sts:AssumeRole"}]}');

INSERT INTO iam.role_attached_policies(role_id, managed_policy_id) VALUES
('EXAMPLEROLEID123', 'AAAABBBBCCCCDDDD');

INSERT INTO iam.role_inline_policies(role_id, policy_name_lower, policy_name_cased, policy_document) VALUES
('EXAMPLEROLEID123', 'example-role-inline-policy-1', 'Example-Role-Inline-Policy-1', '{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"lambda:*","Resource":"*"}]}');

INSERT INTO iam.session_token_encryption_keys(session_token_encryption_key_id, encryption_algorithm, encryption_key, issue_valid_from, issue_expires_at, accept_expires_at) VALUES
('TK1', 'AES256-GCM', 'exampleencryptionkey', '2024-01-01T00:00:00Z', '2024-01-02T00:00:00Z', '2024-01-02T12:00:00Z');