CREATE SCHEMA iam;
COMMENT ON SCHEMA iam IS 'Schema for Identity and Access Management (IAM) data.';

CREATE TABLE iam.accounts(
    account_id CHAR(12) PRIMARY KEY,
    email VARCHAR(256),
    alias VARCHAR(63),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.accounts IS 'An account in the partition.';

CREATE TABLE iam.password_hash_algorithms(
    password_hash_algorithm_id VARCHAR(32) PRIMARY KEY,
    algorithm_name VARCHAR(32) NOT NULL,
    parameters JSONB
);
COMMENT ON TABLE iam.password_hash_algorithms IS 'Supported password hash algorithms for IAM user login profiles.';

CREATE TABLE iam.managed_policies(
    managed_policy_id VARCHAR(32) PRIMARY KEY,
    account_id CHAR(12) NOT NULL,
    managed_policy_name_lower VARCHAR(128) NOT NULL,
    managed_policy_name_cased VARCHAR(128) NOT NULL,
    path VARCHAR(512) NOT NULL,
    default_version BIGINT,
    deprecated BOOLEAN NOT NULL,
    policy_type VARCHAR(32),
    latest_version BIGINT,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_mp_acctid_polname UNIQUE(account_id, managed_policy_name_lower),
    CONSTRAINT ck_mp_polname_lower CHECK (managed_policy_name_lower = LOWER(managed_policy_name_cased)),
    CONSTRAINT ck_mp_path CHECK (path LIKE '/%' AND path LIKE '%/' AND path NOT LIKE '%//%'),
    CONSTRAINT fk_mp_acctid FOREIGN KEY (account_id) REFERENCES iam.accounts(account_id)
);
COMMENT ON TABLE iam.managed_policies IS 'IAM managed policy (AWS or customer). AWS policies are defined by account_id = ''000000000000''.';
COMMENT ON COLUMN iam.managed_policies.managed_policy_id IS 'Unique identifier for the managed policy without the leading ANPA prefix.';

CREATE TABLE iam.managed_policy_versions(
    managed_policy_id VARCHAR(32) NOT NULL,
    managed_policy_version BIGINT NOT NULL CHECK (managed_policy_version > 0),
    policy_document TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_mpv PRIMARY KEY (managed_policy_id, managed_policy_version),
    CONSTRAINT fk_mpv_mp_id FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
);
COMMENT ON TABLE iam.managed_policy_versions IS 'Version of an IAM managed policy.';

CREATE TABLE iam.users(
    user_id VARCHAR(32) PRIMARY KEY,
    account_id CHAR(12) NOT NULL,
    user_name_lower VARCHAR(64) NOT NULL,
    user_name_cased VARCHAR(64) NOT NULL,
    path VARCHAR(512) NOT NULL,
    permissions_boundary_managed_policy_id CHAR(17),
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_iu_acctid_uname UNIQUE(account_id, user_name_lower),
    CONSTRAINT ck_iu_uname_lower CHECK (user_name_lower = LOWER(user_name_cased)),
    CONSTRAINT ck_iu_path CHECK (path LIKE '/%' AND path LIKE '%/' AND path NOT LIKE '%//%'),
    CONSTRAINT fk_iu_acctid FOREIGN KEY (account_id) REFERENCES iam.accounts(account_id),
    CONSTRAINT fk_iu_pbmp FOREIGN KEY (permissions_boundary_managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
);
COMMENT ON TABLE iam.users IS 'IAM users.';
COMMENT ON COLUMN iam.users.user_id IS 'Unique identifier for the user without the leading AIDA prefix.';

CREATE TABLE iam.user_attached_policies(
    user_id VARCHAR(32) PRIMARY KEY,
    managed_policy_id VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_iuap_userid FOREIGN KEY (user_id) REFERENCES iam.users(user_id),
    CONSTRAINT fk_iuap_mp_id FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
);
COMMENT ON TABLE iam.user_attached_policies IS 'Managed policies attached to IAM users.';

CREATE TABLE iam.user_inline_policies(
    user_id VARCHAR(32) NOT NULL,
    policy_name_lower VARCHAR(128) NOT NULL,
    policy_name_cased VARCHAR(128) NOT NULL,
    policy_document TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_iuip PRIMARY KEY (user_id, policy_name_lower),
    CONSTRAINT ck_iuip_policy_name_lower CHECK (policy_name_lower = LOWER(policy_name_cased)),
    CONSTRAINT fk_iuip_userid FOREIGN KEY (user_id) REFERENCES iam.users(user_id)
);
COMMENT ON TABLE iam.user_inline_policies IS 'Inline policies attached to IAM users.';
COMMENT ON COLUMN iam.user_inline_policies.user_id IS 'IAM user id without the leading AIDA prefix.';
COMMENT ON COLUMN iam.user_inline_policies.policy_name_lower IS 'Lowercase version of the policy name; this must be unique per user.';

CREATE TABLE iam.user_login_profiles(
    user_id VARCHAR(32) PRIMARY KEY,
    password_hash_algorithm_id VARCHAR(256) NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    password_reset_required BOOLEAN NOT NULL,
    password_last_changed_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    last_used_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT fk_iulp_userid FOREIGN KEY (user_id) REFERENCES iam.users(user_id),
    CONSTRAINT fk_iulp_password_hash_algorithm_id FOREIGN KEY (password_hash_algorithm_id) REFERENCES iam.password_hash_algorithms(password_hash_algorithm_id)
);
COMMENT ON TABLE iam.user_login_profiles IS 'IAM user passwords (hashed) for logging into the console.';
COMMENT ON COLUMN iam.user_login_profiles.user_id IS 'IAM user id without the leading AIDA prefix.';

CREATE TABLE iam.user_password_history(
    user_id VARCHAR(32) NOT NULL,
    password_hash_algorithm VARCHAR(32) NOT NULL,
    password_hash VARCHAR(256) NOT NULL,
    password_created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    password_changed_at TIMESTAMP WITH TIME ZONE NOT NULL
);
COMMENT ON TABLE iam.user_password_history IS 'Previously used hashed passwords (to check for password reuse).';
COMMENT ON COLUMN iam.user_password_history.user_id IS 'IAM user id without the leading AIDA prefix.';

CREATE TABLE iam.user_credentials(
    access_key_id VARCHAR(32) PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL,
    secret_key VARCHAR(256) NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_iuc_userid FOREIGN KEY (user_id) REFERENCES iam.users(user_id)
);
COMMENT ON TABLE iam.user_credentials IS 'Static access/secret keys for API access.';
COMMENT ON COLUMN iam.user_credentials.access_key_id IS 'Unique identifier for the access key without the leading AKIA prefix.';

CREATE TABLE iam.user_service_specific_credentials(
    service_specific_credential_id VARCHAR(32) PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL,
    service_name VARCHAR(64) NOT NULL,
    service_user_name VARCHAR(64) NOT NULL,
    service_password VARCHAR(256) NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_iussc_userid FOREIGN KEY (user_id) REFERENCES iam.users(user_id)
);
COMMENT ON TABLE iam.user_service_specific_credentials IS 'Service-specific credentials for CodeCommit, Cassandra, etc.';
COMMENT ON COLUMN iam.user_service_specific_credentials.service_specific_credential_id IS 'Unique identifier for the service-specific credential without the leading ASSC prefix.';

CREATE TABLE iam.user_ssh_public_keys(
    ssh_public_key_id VARCHAR(32) PRIMARY KEY,
    user_id VARCHAR(32) NOT NULL,
    fingerprint VARCHAR(64) NOT NULL,
    ssh_public_key_body TEXT NOT NULL,
    enabled BOOLEAN NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_iuspk_userid FOREIGN KEY (user_id) REFERENCES iam.users(user_id)
);
COMMENT ON TABLE iam.user_ssh_public_keys IS 'SSH public keys for CodeCommit.';
COMMENT ON COLUMN iam.user_ssh_public_keys.ssh_public_key_id IS 'Unique identifier for the SSH public key without the leading APKA prefix.';
COMMENT ON COLUMN iam.user_ssh_public_keys.user_id IS 'IAM user id without the leading AIDA prefix.';


CREATE TABLE iam.groups(
    group_id VARCHAR(32) PRIMARY KEY,
    account_id CHAR(12) NOT NULL,
    group_name_lower VARCHAR(64) NOT NULL,
    group_name_cased VARCHAR(64) NOT NULL,
    path VARCHAR(512) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT ck_ig_group_name_lower CHECK (group_name_lower = LOWER(group_name_cased)),
    CONSTRAINT ck_path CHECK (path LIKE '/%' AND path LIKE '%/' AND path NOT LIKE '%//%'),
    CONSTRAINT uk_ig_acctid_gname UNIQUE(account_id, group_name_lower),
    CONSTRAINT fk_ig_acctid FOREIGN KEY (account_id) REFERENCES iam.accounts(account_id)
);
COMMENT ON TABLE iam.groups IS 'IAM groups.';
COMMENT ON COLUMN iam.groups.group_id IS 'Unique identifier for the group without the leading AGPA prefix.';

CREATE TABLE iam.group_attached_policies(
    group_id VARCHAR(32),
    managed_policy_id VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT fk_igap_groupid FOREIGN KEY (group_id) REFERENCES iam.groups(group_id),
    CONSTRAINT fk_igap_mp_id FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
);
COMMENT ON TABLE iam.group_attached_policies IS 'Managed policies attached to IAM groups.';
COMMENT ON COLUMN iam.group_attached_policies.group_id IS 'IAM group id without the leading AGPA prefix.';
COMMENT ON COLUMN iam.group_attached_policies.managed_policy_id IS 'Managed policy id without the leading ANPA prefix.';

CREATE TABLE iam.group_inline_policies(
    group_id VARCHAR(32) NOT NULL,
    policy_name_lower VARCHAR(128) NOT NULL,
    policy_name_cased VARCHAR(128) NOT NULL,
    policy_document TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT pk_igip PRIMARY KEY (group_id, policy_name_lower),
    CONSTRAINT ck_igip_policy_name_lower CHECK (policy_name_lower = LOWER(policy_name_cased)),
    CONSTRAINT fk_igip_groupid FOREIGN KEY (group_id) REFERENCES iam.groups(group_id)
);
COMMENT ON TABLE iam.group_inline_policies IS 'Inline policies attached to IAM groups.';
COMMENT ON COLUMN iam.group_inline_policies.group_id IS 'IAM group id without the leading AGPA prefix.';
COMMENT ON COLUMN iam.group_inline_policies.policy_name_lower IS 'Lowercase version of the policy name; this must be unique per group.';

CREATE TABLE iam.group_members(
    group_id VARCHAR(32) NOT NULL,
    user_id VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (group_id, user_id),
    FOREIGN KEY (group_id) REFERENCES iam.groups(group_id) ON DELETE CASCADE,
    FOREIGN KEY (user_id) REFERENCES iam.users(user_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.group_members IS 'User memberships in IAM groups.';
COMMENT ON COLUMN iam.group_members.group_id IS 'IAM group id without the leading AGPA prefix.';
COMMENT ON COLUMN iam.group_members.user_id IS 'IAM user id without the leading AIDA prefix.';

CREATE TABLE iam.roles(
    role_id VARCHAR(32) PRIMARY KEY,
    account_id CHAR(12) NOT NULL,
    role_name_lower VARCHAR(64) NOT NULL,
    role_name_cased VARCHAR(64) NOT NULL,
    path VARCHAR(512) NOT NULL,
    permissions_boundary_managed_policy_id VARCHAR(32),
    description VARCHAR(1024),
    assume_role_policy_document TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    CONSTRAINT uk_irole_name UNIQUE (account_id, role_name_lower),
    CONSTRAINT ck_irole_name_lower CHECK (role_name_lower = LOWER(role_name_cased)),
    CONSTRAINT ck_irole_path CHECK (path LIKE '/%' AND path LIKE '%/' AND path NOT LIKE '%//%'),
    CONSTRAINT fk_irole_acctid FOREIGN KEY (account_id) REFERENCES iam.accounts(account_id),
    CONSTRAINT fk_irole_permissions_boundary_managed_policy_id FOREIGN KEY (permissions_boundary_managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id)
);
COMMENT ON TABLE iam.roles IS 'IAM roles.';
COMMENT ON COLUMN iam.roles.role_id IS 'Unique identifier for the role without the leading AROA prefix.';

CREATE TABLE iam.role_inline_policies(
    role_id VARCHAR(32) NOT NULL,
    policy_name_lower VARCHAR(128) NOT NULL,
    policy_name_cased VARCHAR(128) NOT NULL,
    policy_document TEXT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, policy_name_lower),
    CONSTRAINT ck_irole_inline_policy_name_lower CHECK (policy_name_lower = LOWER(policy_name_cased)),
    FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.role_inline_policies IS 'Inline policies attached to IAM roles.';
COMMENT ON COLUMN iam.role_inline_policies.role_id IS 'IAM role id without the leading AROA prefix.';
COMMENT ON COLUMN iam.role_inline_policies.policy_name_lower IS 'Lowercase version of the policy name; this must be unique per role.';

CREATE TABLE iam.role_attached_policies(
    role_id VARCHAR(32) NOT NULL,
    managed_policy_id VARCHAR(32) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (role_id, managed_policy_id),
    FOREIGN KEY (role_id) REFERENCES iam.roles(role_id) ON DELETE CASCADE,
    FOREIGN KEY (managed_policy_id) REFERENCES iam.managed_policies(managed_policy_id) ON DELETE CASCADE
);
COMMENT ON TABLE iam.role_attached_policies IS 'Managed policies attached to IAM roles.';
COMMENT ON COLUMN iam.role_attached_policies.role_id IS 'IAM role id without the leading AROA prefix.';
COMMENT ON COLUMN iam.role_attached_policies.managed_policy_id IS 'Managed policy id without the leading ANPA prefix.';

CREATE TABLE iam.role_session_token_keys(
    role_token_id VARCHAR(64) PRIMARY KEY,
    encryption_algorithm VARCHAR(64) NOT NULL,
    encryption_key VARCHAR(64) NOT NULL,
    valid_from TIMESTAMP WITH TIME ZONE NOT NULL,
    expires_at TIMESTAMP WITH TIME ZONE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL DEFAULT CURRENT_TIMESTAMP
);
COMMENT ON TABLE iam.role_session_token_keys IS 'Encryption keys for IAM role session tokens.';