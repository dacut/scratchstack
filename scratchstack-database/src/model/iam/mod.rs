//! Database object models for the default database implementation.
mod account;
mod database;
mod group;
mod group_attached_policy;
mod group_inline_policy;
mod group_membership;
mod managed_policy;
mod managed_policy_version;
mod password_hash_algorithm;
mod role;
mod role_attached_policy;
mod role_inline_policy;
mod role_session_token_key;
mod user;
mod user_attached_policy;
mod user_credential;
mod user_inline_policy;
mod user_login_profile;
mod user_password_history;
pub use {
    account::*, database::*, group::*, group_attached_policy::*, group_inline_policy::*, group_membership::*,
    managed_policy::*, managed_policy_version::*, role::*, role_attached_policy::*, role_inline_policy::*,
    role_session_token_key::*, user::*, user_attached_policy::*, user_credential::*, user_inline_policy::*,
    user_login_profile::*, user_password_history::*, password_hash_algorithm::*
};
