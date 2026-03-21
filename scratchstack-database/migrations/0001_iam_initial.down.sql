--- Drop tables in the reverse order of creation to avoid foreign key constraints
DROP TABLE IF EXISTS iam.role_session_token_keys;
DROP TABLE IF EXISTS iam.role_inline_policies;
DROP TABLE IF EXISTS iam.role_attached_policies;
DROP TABLE IF EXISTS iam.roles;
DROP TABLE IF EXISTS iam.group_memberships;
DROP TABLE IF EXISTS iam.group_inline_policies;
DROP TABLE IF EXISTS iam.group_attached_policies;
DROP TABLE IF EXISTS iam.groups;
DROP TABLE IF EXISTS iam.user_password_history;
DROP TABLE IF EXISTS iam.user_login_profiles;
DROP TABLE IF EXISTS iam.user_credentials;
DROP TABLE IF EXISTS iam.user_attached_policies;
DROP TABLE IF EXISTS iam.user_inline_policies;
DROP TABLE IF EXISTS iam.user_ssh_public_keys;
DROP TABLE IF EXISTS iam.user_service_specific_credentials;
DROP TABLE IF EXISTS iam.users;
DROP TABLE IF EXISTS iam.managed_policy_versions;
DROP TABLE IF EXISTS iam.managed_policies;
DROP TABLE IF EXISTS iam.password_hash_algorithms;
DROP TABLE IF EXISTS iam.accounts;

--- History tables; can be dropped in any order
DROP TABLE IF EXISTS iam.deleted_accounts;
DROP TABLE IF EXISTS iam.deleted_managed_policies;
DROP TABLE IF EXISTS iam.deleted_managed_policy_versions;
DROP TABLE IF EXISTS iam.deleted_iam_users;
DROP TABLE IF EXISTS iam.deleted_iam_user_attached_policies;
DROP TABLE IF EXISTS iam.deleted_iam_user_inline_policies;
DROP TABLE IF EXISTS iam.deleted_iam_user_ssh_public_keys;
DROP TABLE IF EXISTS iam.deleted_iam_user_credentials;
DROP TABLE IF EXISTS iam.deleted_iam_user_login_profiles;
DROP TABLE IF EXISTS iam.deleted_iam_user_service_specific_credentials;
DROP TABLE IF EXISTS iam.deleted_iam_group_attached_policies;
DROP TABLE IF EXISTS iam.deleted_iam_group_inline_policies;
DROP TABLE IF EXISTS iam.deleted_iam_group_memberships;
DROP TABLE IF EXISTS iam.deleted_iam_groups;
DROP TABLE IF EXISTS iam.deleted_iam_role_attached_policies;
DROP TABLE IF EXISTS iam.deleted_iam_role_inline_policies;
DROP TABLE IF EXISTS iam.deleted_iam_role_session_token_keys;
DROP TABLE IF EXISTS iam.deleted_iam_roles;

DROP SCHEMA IF EXISTS iam;