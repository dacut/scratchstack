use chrono::NaiveDateTime;
use diesel::Queryable;

#[derive(Debug, Queryable, PartialEq)]
pub struct IamAccount {
    pub account_id: String,
    pub email: Option<String>,
    pub active: bool,
    pub alias: Option<String>,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamGroup {
    pub group_id: String,
    pub account_id: String,
    pub group_name_lower: String,
    pub group_name_cased: String,
    pub path: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamGroupAttachedPolicy {
    pub group_id: String,
    pub managed_policy_id: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamGroupInlinePolicy {
    pub group_id: String,
    pub policy_name_lower: String,
    pub policy_name_cased: String,
    pub policy_document: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamGroupMember {
    pub group_id: String,
    pub user_id: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamRole {
    pub role_id: String,
    pub account_id: String,
    pub role_name_lower: String,
    pub role_name_cased: String,
    pub path: String,
    pub permissions_boundary_managed_policy_id: Option<String>,
    pub description: Option<String>,
    pub assume_role_policy_document: String,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamRoleAttachedPolicy {
    pub role_id: String,
    pub managed_policy_id: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamRoleInlinePolicy {
    pub role_id: String,
    pub policy_name_lower: String,
    pub policy_name_cased: String,
    pub policy_document: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamRoleTokenKey {
    pub access_key_id: String,
    pub encryption_algorithm: String,
    pub encryption_key: Vec<u8>,
    pub valid_at: NaiveDateTime,
    pub expires_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUser {
    pub user_id: String,
    pub account_id: String,
    pub user_name_lower: String,
    pub user_name_cased: String,
    pub path: String,
    pub permissions_boundary_managed_policy_id: Option<String>,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserAttachedPolicy {
    pub user_id: String,
    pub managed_policy_id: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserCredential {
    pub user_id: String,
    pub access_key_id: String,
    pub secret_key: String,
    pub active: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserInlinePolicy {
    pub user_id: String,
    pub policy_name_lower: String,
    pub policy_name_cased: String,
    pub policy_document: String,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserLoginProfile {
    pub user_id: String,
    pub password_hash_algorithm: String,
    pub password_hash: String,
    pub password_reset_required: bool,
    pub password_last_changed_at: NaiveDateTime,
    pub created_at: NaiveDateTime,
    pub last_used_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserPasswordHistory {
    pub user_id: String,
    pub password_hash_algorithm: String,
    pub password_hash: String,
    pub password_changed_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserServiceSpecificCredential {
    pub user_id: String,
    pub service_specific_credential_id: String,
    pub service_name: String,
    pub service_password: String,
    pub active: bool,
    pub created_at: NaiveDateTime,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct IamUserSshPublicKey {
    pub user_id: String,
    pub public_key_id: String,
    pub fingerprint: String,
    pub ssh_public_key_body: String,
    pub active: bool,
    pub created_at: NaiveDateTime
}

#[derive(Debug, Queryable, PartialEq)]
pub struct ManagedPolicy {
    pub managed_policy_id: String,
    pub account_id: String,
    pub managed_policy_name_lower: String,
    pub managed_policy_name_cased: String,
    pub path: String,
    pub default_version: Option<i128>,
    pub deprecated: bool,
    pub policy_type: Option<String>,
    pub created_at: NaiveDateTime,
    pub last_version: Option<i128>,
}

#[derive(Debug, Queryable, PartialEq)]
pub struct ManagedPolicyVersion {
    pub managed_policy_id: String,
    pub version: i128,
    pub policy_document: String,
    pub created_at: NaiveDateTime,
}