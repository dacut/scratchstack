table! {
    iam.account (account_id) {
        account_id -> Varchar,
        email -> Varchar,
        active -> Bool,
        alias -> Nullable<Varchar>,
    }
}

table! {
    iam.deleted_iam_group (group_id) {
        group_id -> Varchar,
        account_id -> Nullable<Varchar>,
        group_name_lower -> Nullable<Varchar>,
        group_name_cased -> Nullable<Varchar>,
        path -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        deleted_at -> Nullable<Timestamp>,
    }
}

table! {
    iam.deleted_iam_role (role_id) {
        role_id -> Varchar,
        account_id -> Nullable<Varchar>,
        role_name_lower -> Nullable<Varchar>,
        role_name_cased -> Nullable<Varchar>,
        path -> Nullable<Varchar>,
        permissions_boundary_managed_policy_id -> Nullable<Varchar>,
        description -> Nullable<Varchar>,
        assume_role_policy_document -> Nullable<Text>,
        created_at -> Nullable<Timestamp>,
    }
}

table! {
    iam.deleted_iam_user (user_id) {
        user_id -> Varchar,
        account_id -> Nullable<Varchar>,
        user_name_lower -> Nullable<Varchar>,
        user_name_cased -> Nullable<Varchar>,
        path -> Nullable<Varchar>,
        permissions_boundary_managed_policy_id -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        deleted_at -> Nullable<Timestamp>,
    }
}

table! {
    iam.deleted_managed_policy (managed_policy_id) {
        managed_policy_id -> Varchar,
        account_id -> Nullable<Varchar>,
        managed_policy_name_lower -> Nullable<Varchar>,
        managed_policy_name_cased -> Nullable<Varchar>,
        path -> Nullable<Varchar>,
        default_version -> Nullable<Int8>,
        deprecated -> Nullable<Bool>,
        policy_type -> Nullable<Varchar>,
        created_at -> Nullable<Timestamp>,
        deleted_at -> Nullable<Timestamp>,
    }
}

table! {
    iam.deleted_managed_policy_version (managed_policy_id, version) {
        managed_policy_id -> Varchar,
        #[sql_name = "managed_policy_version"]
        version -> Int8,
        policy_document -> Text,
        created_at -> Timestamp,
        deleted_at -> Timestamp,
    }
}

table! {
    iam.iam_group (group_id) {
        group_id -> Varchar,
        account_id -> Varchar,
        group_name_lower -> Varchar,
        group_name_cased -> Varchar,
        path -> Varchar,
        created_at -> Timestamp,
    }
}

table! {
    iam.iam_group_attached_policy (group_id, managed_policy_id) {
        group_id -> Varchar,
        managed_policy_id -> Varchar,
    }
}

table! {
    iam.iam_group_inline_policy (group_id, policy_name_lower) {
        group_id -> Varchar,
        policy_name_lower -> Varchar,
        policy_name_cased -> Varchar,
        policy_document -> Text,
    }
}

table! {
    iam.iam_group_member (group_id, user_id) {
        group_id -> Varchar,
        user_id -> Varchar,
    }
}

table! {
    iam.iam_role (role_id) {
        role_id -> Varchar,
        account_id -> Varchar,
        role_name_lower -> Varchar,
        role_name_cased -> Varchar,
        path -> Varchar,
        permissions_boundary_managed_policy_id -> Nullable<Varchar>,
        description -> Nullable<Varchar>,
        assume_role_policy_document -> Text,
        created_at -> Timestamp,
    }
}

table! {
    iam.iam_role_attached_policy (role_id, managed_policy_id) {
        role_id -> Varchar,
        managed_policy_id -> Varchar,
    }
}

table! {
    iam.iam_role_inline_policy (role_id, policy_name_lower) {
        role_id -> Varchar,
        policy_name_lower -> Varchar,
        policy_name_cased -> Varchar,
        policy_document -> Text,
    }
}

table! {
    iam.iam_role_token_key (access_key_id) {
        access_key_id -> Varchar,
        encryption_algorithm -> Varchar,
        encryption_key -> Bytea,
        valid_at -> Timestamp,
        expires_at -> Timestamp,
    }
}

table! {
    iam.iam_user (user_id) {
        user_id -> Varchar,
        account_id -> Varchar,
        user_name_lower -> Varchar,
        user_name_cased -> Varchar,
        path -> Varchar,
        permissions_boundary_managed_policy_id -> Nullable<Varchar>,
        created_at -> Timestamp,
    }
}

table! {
    iam.iam_user_attached_policy (user_id, managed_policy_id) {
        user_id -> Varchar,
        managed_policy_id -> Varchar,
    }
}

table! {
    iam.iam_user_credential (user_id, access_key_id) {
        user_id -> Varchar,
        access_key_id -> Varchar,
        secret_key -> Varchar,
        active -> Bool,
        created_at -> Timestamp,
    }
}

table! {
    iam.iam_user_inline_policy (user_id, policy_name_lower) {
        user_id -> Varchar,
        policy_name_lower -> Varchar,
        policy_name_cased -> Varchar,
        policy_document -> Text,
    }
}

table! {
    iam.iam_user_login_profile (user_id) {
        user_id -> Varchar,
        password_hash_algorithm -> Varchar,
        password_hash -> Varchar,
        password_reset_required -> Bool,
        password_last_changed_at -> Timestamp,
        created_at -> Timestamp,
        last_used_at -> Nullable<Timestamp>,
    }
}

table! {
    iam.iam_user_password_history (user_id, password_changed_at) {
        user_id -> Varchar,
        password_hash_algorithm -> Varchar,
        password_hash -> Varchar,
        password_changed_at -> Timestamp,
    }
}

table! {
    iam.iam_user_service_specific_credential (user_id, service_specific_credential_id) {
        user_id -> Varchar,
        service_specific_credential_id -> Varchar,
        service_name -> Varchar,
        service_password -> Varchar,
        active -> Bool,
        created_at -> Timestamp,
    }
}

table! {
    iam.iam_user_ssh_public_key (user_id, public_key_id) {
        user_id -> Varchar,
        public_key_id -> Varchar,
        fingerprint -> Varchar,
        ssh_public_key_body -> Text,
        active -> Bool,
        created_at -> Timestamp,
    }
}

table! {
    iam.managed_policy (managed_policy_id) {
        managed_policy_id -> Varchar,
        account_id -> Varchar,
        managed_policy_name_lower -> Varchar,
        managed_policy_name_cased -> Varchar,
        path -> Varchar,
        default_version -> Nullable<Int8>,
        deprecated -> Bool,
        policy_type -> Nullable<Varchar>,
        created_at -> Timestamp,
        last_version -> Nullable<Int8>,
    }
}

table! {
    iam.managed_policy_version (managed_policy_id, version) {
        managed_policy_id -> Varchar,
        #[sql_name = "managed_policy_version"]
        version -> Int8,
        policy_document -> Text,
        created_at -> Timestamp,
    }
}

joinable!(iam_group_attached_policy -> iam_group (group_id));
joinable!(iam_group_attached_policy -> managed_policy (managed_policy_id));
joinable!(iam_group_inline_policy -> iam_group (group_id));
joinable!(iam_group_member -> iam_group (group_id));
joinable!(iam_group_member -> iam_user (user_id));
joinable!(iam_role_attached_policy -> iam_role (role_id));
joinable!(iam_role_attached_policy -> managed_policy (managed_policy_id));
joinable!(iam_role_inline_policy -> iam_role (role_id));
joinable!(iam_user -> managed_policy (permissions_boundary_managed_policy_id));
joinable!(iam_user_attached_policy -> iam_user (user_id));
joinable!(iam_user_attached_policy -> managed_policy (managed_policy_id));
joinable!(iam_user_credential -> iam_user (user_id));
joinable!(iam_user_inline_policy -> iam_user (user_id));
joinable!(iam_user_login_profile -> iam_user (user_id));
joinable!(iam_user_password_history -> iam_user (user_id));
joinable!(iam_user_service_specific_credential -> iam_user (user_id));
joinable!(iam_user_ssh_public_key -> iam_user (user_id));
joinable!(managed_policy -> account (account_id));
joinable!(managed_policy_version -> managed_policy (managed_policy_id));

allow_tables_to_appear_in_same_query!(
    account,
    deleted_iam_group,
    deleted_iam_role,
    deleted_iam_user,
    deleted_managed_policy,
    deleted_managed_policy_version,
    iam_group,
    iam_group_attached_policy,
    iam_group_inline_policy,
    iam_group_member,
    iam_role,
    iam_role_attached_policy,
    iam_role_inline_policy,
    iam_role_token_key,
    iam_user,
    iam_user_attached_policy,
    iam_user_credential,
    iam_user_inline_policy,
    iam_user_login_profile,
    iam_user_password_history,
    iam_user_service_specific_credential,
    iam_user_ssh_public_key,
    managed_policy,
    managed_policy_version,
);
