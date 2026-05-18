//! Tests for the IAM database model and related functionality.
#![cfg(all(feature = "iam", feature = "utils"))]
#![warn(clippy::all)]
#![allow(clippy::manual_range_contains)]
#![deny(
    missing_docs,
    rustdoc::bare_urls,
    rustdoc::broken_intra_doc_links,
    rustdoc::invalid_codeblock_attributes,
    rustdoc::invalid_html_tags,
    rustdoc::private_intra_doc_links,
    rustdoc::unescaped_backticks
)]
#![cfg_attr(doc, feature(doc_cfg))]

use {
    pretty_assertions::{assert_eq, assert_ne},
    scratchstack_database::{Loadable, model::iam, ops::RequestExecutor, utils::TempDatabase},
    scratchstack_shapes_iam::{
        error_meta::Error as IamError,
        operation::{
            AddUserToGroupInternalRequest, CreateAccountRequest, CreateGroupInternalRequest,
            CreatePolicyInternalRequest, CreatePolicyVersionRequest, CreateUserInternalRequest,
            DeleteGroupInternalRequest, DeletePolicyVersionRequest, GetCurrentPartitionRequest,
            GetGroupInternalRequest, GetPolicyRequest, GetPolicyVersionRequest, GetUserInternalRequest,
            ListAccountsRequest, ListGroupsForUserInternalRequest, ListGroupsInternalRequest,
            ListPoliciesInternalRequest, ListPolicyVersionsRequest, ListUserTagsInternalRequest,
            RemoveUserFromGroupInternalRequest, SetCurrentPartitionRequest, SetDefaultPolicyVersionRequest,
            TagPolicyRequest, TagUserInternalRequest, UntagPolicyRequest, UntagUserInternalRequest,
            UpdateGroupInternalRequest,
        },
        types::{ListAccountsFilter, ListAccountsFilterName, PolicyScopeType, PolicyUsageType, Tag},
    },
};

/// Test all of the features of the database.
///
/// We do this instead of more granular testing because the database we're running against is typically stateful.
#[test_log::test(tokio::test)]
async fn test_database() {
    let iam_data: iam::Database =
        serde_json::from_str(TEST_DATA).expect("Failed to deserialize test data into IAM database model");

    let mut database = TempDatabase::new().await.expect("Failed to create temporary database");
    database.bootstrap().await.expect("Failed to set up, start, and bootstrap PostgreSQL database");
    let pool =
        database.get_scratchstack_pool().await.expect("Failed to get PostgreSQL connection pool for scratchstack user");

    let mut c = pool.acquire().await.expect("Failed to acquire connection from pool");
    iam::MIGRATOR.run(&mut *c).await.expect("Failed to run database migrations");
    let rows_affected = iam_data.load_into(&mut c).await.expect("Failed to load IAM data into database");
    eprintln!("Loaded {rows_affected} rows of IAM data into database");

    // -- SetCurrentPartition and GetCurrentPartition --------------------------
    test_invalid_set_current_partition(&pool).await;
    test_set_current_partition(&pool).await;
    test_get_current_partition(&pool).await;

    let iam_dump = iam::Database::dump_from(&mut c).await.expect("Failed to dump IAM data from database");
    assert_ne!(iam_data, iam_dump, "Dumped IAM data should not be equal to original IAM data due to created_at fields");
    let iam_dump2 =
        iam::Database::dump_from(&mut c).await.expect("Failed to dump IAM data from database a second time");
    assert_eq!(iam_dump, iam_dump2, "Dumped IAM data should be equal across multiple dumps");

    // -- CreateAccountRequest -------------------------------------------------
    test_create_account_specific_id(&pool).await;
    test_create_account_with_email_and_alias(&pool).await;
    test_create_account_random_id(&pool).await;
    test_create_account_duplicate_id(&pool).await;
    test_create_account_invalid_id(&pool).await;
    test_create_account_invalid_alias_leading_dash(&pool).await;
    test_create_account_alias_too_short(&pool).await;
    test_create_account_organization_id_unsupported(&pool).await;
    test_list_accounts_explicit(&pool).await;
    test_create_350_accounts(&pool).await;
    test_list_350_accounts(&pool).await;
    test_list_accounts_filter_single_account_id(&pool).await;
    test_list_accounts_filter_multiple_account_ids(&pool).await;
    test_list_accounts_filter_by_email(&pool).await;
    test_list_accounts_filter_by_alias(&pool).await;
    test_list_accounts_filter_combined_match(&pool).await;
    test_list_accounts_filter_combined_no_match(&pool).await;
    test_list_accounts_filter_nonexistent(&pool).await;

    // -- CreateUserRequestInternal --------------------------------------------
    test_create_user_simple(&pool).await;
    test_create_user_with_path(&pool).await;
    test_create_user_with_tags(&pool).await;
    test_create_user_with_permissions_boundary(&pool).await;
    test_create_user_duplicate_name(&pool).await;
    test_create_user_invalid_name();
    test_create_user_nonexistent_account(&pool).await;
    test_create_user_nonexistent_permissions_boundary(&pool).await;

    // -- TagUserInternalRequest / UntagUserInternalRequest --------------------
    test_tag_user(&pool).await;
    test_tag_user_upsert(&pool).await;
    test_tag_user_empty_tags(&pool).await;
    test_tag_user_nonexistent_user(&pool).await;
    test_untag_user(&pool).await;
    test_untag_user_empty_keys(&pool).await;
    test_untag_user_nonexistent_key(&pool).await;
    test_untag_user_nonexistent_user(&pool).await;

    // -- GetUserInternalRequest -----------------------------------------------
    test_get_user_simple(&pool).await;
    test_get_user_with_tags(&pool).await;
    test_get_user_nonexistent(&pool).await;
    test_get_user_no_user_name(&pool).await;

    // -- CreateGroupInternalRequest -------------------------------------------
    test_create_group_simple(&pool).await;
    test_create_group_with_path(&pool).await;
    test_create_group_duplicate_name(&pool).await;
    test_create_group_nonexistent_account(&pool).await;
    test_create_group_max_length_name(&pool).await;

    // -- GetGroupInternalRequest ----------------------------------------------
    test_get_group_simple(&pool).await;
    test_get_group_with_path(&pool).await;
    test_get_group_nonexistent(&pool).await;

    // -- ListGroupsInternalRequest --------------------------------------------
    test_list_groups(&pool).await;
    test_list_groups_with_path_prefix(&pool).await;

    // -- UpdateGroupInternalRequest -------------------------------------------
    test_update_group_rename(&pool).await;
    test_update_group_change_path(&pool).await;
    test_update_group_nonexistent(&pool).await;

    // -- AddUserToGroupInternalRequest / RemoveUserFromGroupInternalRequest ---
    test_add_user_to_group(&pool).await;
    test_add_user_to_group_idempotent(&pool).await;
    test_add_user_to_group_nonexistent_group(&pool).await;
    test_add_user_to_group_nonexistent_user(&pool).await;
    test_list_groups_for_user(&pool).await;
    test_list_groups_for_user_nonexistent_user(&pool).await;
    test_remove_user_from_group(&pool).await;
    test_remove_user_from_group_not_member(&pool).await;
    test_remove_user_from_group_nonexistent_group(&pool).await;

    // -- CreatePolicyInternalRequest ------------------------------------------
    test_create_policy_simple(&pool).await;
    test_create_policy_with_path(&pool).await;
    test_create_policy_with_description(&pool).await;
    test_create_policy_with_tags(&pool).await;
    test_create_policy_duplicate_name(&pool).await;
    test_create_policy_invalid_document(&pool).await;
    test_create_policy_valid_json_invalid_aspen(&pool).await;
    test_create_policy_nonexistent_account(&pool).await;

    // -- CreatePolicyVersionRequest -------------------------------------------
    test_create_policy_version_simple(&pool).await;
    test_create_policy_version_set_as_default(&pool).await;
    test_create_policy_version_not_default(&pool).await;
    test_create_policy_version_limit_exceeded(&pool).await;
    test_create_policy_version_mismatched_path(&pool).await;
    test_create_policy_version_nonexistent_policy(&pool).await;
    test_create_policy_version_invalid_document(&pool).await;

    // -- DeletePolicyVersionRequest -------------------------------------------
    test_delete_policy_version_simple(&pool).await;
    test_delete_policy_version_default_fails(&pool).await;
    test_delete_policy_version_with_path(&pool).await;
    test_delete_policy_version_mismatched_path(&pool).await;
    test_delete_policy_version_nonexistent_policy(&pool).await;
    test_delete_policy_version_nonexistent_version(&pool).await;
    test_delete_policy_version_invalid_arn(&pool).await;
    test_delete_policy_version_aws_account(&pool).await;

    // -- update_date denormalization ------------------------------------------
    test_policy_update_date_lifecycle(&pool).await;

    // -- GetPolicyRequest / GetPolicyVersionRequest ---------------------------
    test_get_policy_simple(&pool).await;
    test_get_policy_with_path(&pool).await;
    test_get_policy_aws_account(&pool).await;
    test_get_policy_mismatched_path(&pool).await;
    test_get_policy_nonexistent(&pool).await;
    test_get_policy_version_simple(&pool).await;
    test_get_policy_version_nonexistent_version(&pool).await;
    test_get_policy_version_mismatched_path(&pool).await;

    // -- SetDefaultPolicyVersionRequest ---------------------------------------
    test_set_default_policy_version_simple(&pool).await;
    test_set_default_policy_version_nonexistent_version(&pool).await;
    test_set_default_policy_version_nonexistent_policy(&pool).await;
    test_set_default_policy_version_mismatched_path(&pool).await;
    test_set_default_policy_version_aws_account(&pool).await;

    // -- TagPolicyRequest / UntagPolicyRequest --------------------------------
    test_tag_policy_simple(&pool).await;
    test_tag_policy_upsert(&pool).await;
    test_tag_policy_empty(&pool).await;
    test_tag_policy_nonexistent(&pool).await;
    test_untag_policy_simple(&pool).await;
    test_untag_policy_empty(&pool).await;
    test_untag_policy_nonexistent(&pool).await;

    // -- ListPolicyVersionsRequest --------------------------------------------
    test_list_policy_versions_simple(&pool).await;
    test_list_policy_versions_nonexistent(&pool).await;
    test_list_policy_versions_pagination(&pool).await;

    // -- ListPoliciesInternalRequest ------------------------------------------
    test_list_policies_local(&pool).await;
    test_list_policies_aws(&pool).await;
    test_list_policies_all(&pool).await;
    test_list_policies_path_prefix(&pool).await;
    test_list_policies_only_attached(&pool).await;
    test_list_policies_usage_filter_pb(&pool).await;

    // -- DeleteGroupInternalRequest -------------------------------------------
    test_delete_group_max_length_name(&pool).await;
    test_delete_group(&pool).await;
    test_delete_group_nonexistent(&pool).await;

    iam::MIGRATOR.undo(&mut *c, 0).await.expect("Failed to undo database migrations");
}

async fn test_set_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest::builder()
        .partition("test-partition")
        .build()
        .expect("Failed to build SetCurrentPartitionRequest");
    assert_eq!(req.partition, "test-partition");

    let resp = req.execute(&mut tx).await.expect("Failed to set current partition");
    assert_eq!(resp.partition, "test-partition");
    tx.commit().await.expect("Failed to commit transaction");
}

async fn test_invalid_set_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest {
        partition: "".to_string(),
    };
    let result = req.execute(&mut tx).await;
    assert!(result.is_err(), "Setting an invalid partition ID should fail");
    tx.rollback().await.expect("Failed to rollback transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let req = SetCurrentPartitionRequest {
        partition: "-".to_string(),
    };
    let result = req.execute(&mut tx).await;
    assert!(result.is_err(), "Setting an invalid partition ID should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
}

async fn test_get_current_partition(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");

    let resp = GetCurrentPartitionRequest::builder()
        .build()
        .unwrap()
        .execute(&mut tx)
        .await
        .expect("Failed to get current partition");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.partition.as_deref(), Some("test-partition"));
}

async fn test_create_account_specific_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000001".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with specific ID");
    tx.commit().await.expect("Failed to commit transaction");

    let account = resp.account;
    assert_eq!(account.account_id, "100000000001");
    assert_eq!(account.organization_id, None);
    assert_eq!(account.email, None);
    assert_eq!(account.account_alias, None);
}

async fn test_create_account_with_email_and_alias(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000002".to_string()),
        email: Some("admin@example.com".to_string()),
        account_alias: Some("example-corp".to_string()),
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with email and alias");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.account.account_id, "100000000002");
    assert_eq!(resp.account.email.as_deref(), Some("admin@example.com"));
    assert_eq!(resp.account.account_alias.as_deref(), Some("example-corp"));
}

async fn test_create_account_random_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateAccountRequest {
        organization_id: None,
        account_id: None,
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to create account with random ID");
    tx.commit().await.expect("Failed to commit transaction");

    // The returned account ID must be a 12-digit string.
    assert_eq!(resp.account.account_id.len(), 12, "Random account ID must be 12 digits");
    assert!(resp.account.account_id.chars().all(|c| c.is_ascii_digit()), "Random account ID must be all digits");

    // Verify the account appears in ListAccounts.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec![resp.account.account_id.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(list_resp.accounts.len(), 1);
    assert_eq!(list_resp.accounts[0].account_id, resp.account.account_id);
}

async fn test_create_account_duplicate_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000001".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate account ID must fail");
}

async fn test_create_account_invalid_id(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("12345".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with an invalid ID must fail");
}

async fn test_create_account_invalid_alias_leading_dash(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000003".to_string()),
        email: None,
        account_alias: Some("-bad-alias".to_string()),
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with an invalid alias must fail");
}

async fn test_create_account_alias_too_short(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: None,
        account_id: Some("100000000003".to_string()),
        email: None,
        account_alias: Some("ab".to_string()),
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account with a too-short alias must fail");
}

async fn test_create_account_organization_id_unsupported(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateAccountRequest {
        organization_id: Some("o-12345".to_string()),
        account_id: Some("100000000003".to_string()),
        email: None,
        account_alias: None,
    }
    .execute(&mut tx)
    .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating an account in an organization must fail (unsupported)");
}

async fn test_list_accounts_explicit(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let list_resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec!["100000000001".to_string(), "100000000002".to_string()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(list_resp.accounts.len(), 2);
    assert_eq!(list_resp.accounts[0].account_id, "100000000001");
    assert_eq!(list_resp.accounts[1].account_id, "100000000002");
    assert_eq!(list_resp.accounts[1].email.as_deref(), Some("admin@example.com"));
    assert_eq!(list_resp.accounts[1].account_alias.as_deref(), Some("example-corp"));
    assert_eq!(list_resp.marker, None);
}

const BASE_ACCOUNT_ID: u64 = 876_543_210_000;
const N_BULK_ACCOUNTS: u64 = 350;

async fn test_create_350_accounts(pool: &sqlx::PgPool) {
    // Create 350 accounts with sequential IDs, emails, and aliases.
    for i in 0..N_BULK_ACCOUNTS {
        let account_id = format!("{:012}", BASE_ACCOUNT_ID + i);
        let email = format!("{account_id}@example.com");
        let alias = format!("account-{account_id}");

        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = CreateAccountRequest {
            organization_id: None,
            account_id: Some(account_id.clone()),
            email: Some(email.clone()),
            account_alias: Some(alias.clone()),
        }
        .execute(&mut tx)
        .await
        .unwrap_or_else(|e| panic!("Failed to create account {account_id}: {e}"));
        tx.commit().await.expect("Failed to commit transaction");

        assert_eq!(resp.account.account_id, account_id);
        assert_eq!(resp.account.email.as_deref(), Some(email.as_str()));
        assert_eq!(resp.account.account_alias.as_deref(), Some(alias.as_str()));
    }
}

async fn test_list_350_accounts(pool: &sqlx::PgPool) {
    // Paginate through all accounts, collecting every account in the bulk range.
    let mut all_bulk_accounts = Vec::new();
    let mut marker: Option<String> = None;
    let mut page_count = 0u32;

    loop {
        let mut tx = pool.begin().await.expect("Failed to begin transaction");
        let resp = ListAccountsRequest {
            filters: vec![],
            max_items: Some(100),
            marker: marker.clone(),
        }
        .execute(&mut tx)
        .await
        .expect("Failed to list accounts");
        tx.rollback().await.expect("Failed to rollback transaction");

        page_count += 1;
        for account in resp.accounts {
            let id: u64 = account.account_id.parse().unwrap_or(0);
            if id >= BASE_ACCOUNT_ID && id < BASE_ACCOUNT_ID + N_BULK_ACCOUNTS {
                all_bulk_accounts.push(account);
            }
        }

        marker = resp.marker;
        if marker.is_none() {
            break;
        }
    }

    assert!(page_count > 1, "Expected multiple pages, got {page_count}");
    assert_eq!(
        all_bulk_accounts.len(),
        N_BULK_ACCOUNTS as usize,
        "Expected {N_BULK_ACCOUNTS} bulk accounts across all pages, found {}",
        all_bulk_accounts.len(),
    );

    // Spot-check first, middle, and last accounts.
    for offset in [0, N_BULK_ACCOUNTS / 2, N_BULK_ACCOUNTS - 1] {
        let expected_id = format!("{:012}", BASE_ACCOUNT_ID + offset);
        let expected_email = format!("{expected_id}@example.com");
        let expected_alias = format!("account-{expected_id}");

        let account = all_bulk_accounts
            .iter()
            .find(|a| a.account_id == expected_id)
            .unwrap_or_else(|| panic!("Account {expected_id} not found in paginated results"));

        assert_eq!(account.email.as_deref(), Some(expected_email.as_str()), "Email mismatch for {expected_id}");
        assert_eq!(account.account_alias.as_deref(), Some(expected_alias.as_str()), "Alias mismatch for {expected_id}");
    }
}

/// Return the account ID, email, and alias strings for a bulk account at the given offset.
fn bulk_account(offset: u64) -> (String, String, String) {
    let id = format!("{:012}", BASE_ACCOUNT_ID + offset);
    let email = format!("{id}@example.com");
    let alias = format!("account-{id}");
    (id, email, alias)
}

async fn test_list_accounts_filter_single_account_id(pool: &sqlx::PgPool) {
    let (id, expected_email, expected_alias) = bulk_account(42);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec![id.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by single account ID");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for id {id}");
    assert_eq!(resp.accounts[0].account_id, id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(expected_email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.marker, None);
}

async fn test_list_accounts_filter_multiple_account_ids(pool: &sqlx::PgPool) {
    let offsets = [10u64, 100, 200, 300];
    let ids: Vec<String> = offsets.iter().map(|&o| bulk_account(o).0).collect();

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: ids.clone(),
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by multiple account IDs");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), offsets.len(), "Expected {} accounts", offsets.len());
    // Results are ordered by account_id; our offsets are already ascending.
    for (account, &offset) in resp.accounts.iter().zip(offsets.iter()) {
        let (expected_id, expected_email, expected_alias) = bulk_account(offset);
        assert_eq!(account.account_id, expected_id);
        assert_eq!(account.email.as_deref(), Some(expected_email.as_str()));
        assert_eq!(account.account_alias.as_deref(), Some(expected_alias.as_str()));
    }
    assert_eq!(resp.marker, None);
}

async fn test_list_accounts_filter_by_email(pool: &sqlx::PgPool) {
    let (expected_id, email, expected_alias) = bulk_account(77);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::Email,
            values: vec![email.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by email");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for email {email}");
    assert_eq!(resp.accounts[0].account_id, expected_id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.marker, None);
}

async fn test_list_accounts_filter_by_alias(pool: &sqlx::PgPool) {
    let (expected_id, expected_email, alias) = bulk_account(155);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountAlias,
            values: vec![alias.clone()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts by alias");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account for alias {alias}");
    assert_eq!(resp.accounts[0].account_id, expected_id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(expected_email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(alias.as_str()));
    assert_eq!(resp.marker, None);
}

async fn test_list_accounts_filter_combined_match(pool: &sqlx::PgPool) {
    // AccountId AND Email filters both match the same account — should return it.
    let (id, email, expected_alias) = bulk_account(250);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![
            ListAccountsFilter {
                name: ListAccountsFilterName::AccountId,
                values: vec![id.clone()],
            },
            ListAccountsFilter {
                name: ListAccountsFilterName::Email,
                values: vec![email.clone()],
            },
        ],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with combined matching filters");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 1, "Expected exactly one account when AccountId and Email both match");
    assert_eq!(resp.accounts[0].account_id, id);
    assert_eq!(resp.accounts[0].email.as_deref(), Some(email.as_str()));
    assert_eq!(resp.accounts[0].account_alias.as_deref(), Some(expected_alias.as_str()));
    assert_eq!(resp.marker, None);
}

async fn test_list_accounts_filter_combined_no_match(pool: &sqlx::PgPool) {
    // AccountId and Email filters refer to *different* accounts — the AND should return nothing.
    let (id_a, _, _) = bulk_account(10);
    let (_, email_b, _) = bulk_account(20);

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![
            ListAccountsFilter {
                name: ListAccountsFilterName::AccountId,
                values: vec![id_a.clone()],
            },
            ListAccountsFilter {
                name: ListAccountsFilterName::Email,
                values: vec![email_b.clone()],
            },
        ],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with combined non-matching filters");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(
        resp.accounts.len(),
        0,
        "Expected no accounts when AccountId ({id_a}) and Email ({email_b}) refer to different accounts",
    );
    assert_eq!(resp.marker, None);
}

async fn test_list_accounts_filter_nonexistent(pool: &sqlx::PgPool) {
    // 999999999999 is never created by any test, so this must return no results.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListAccountsRequest {
        filters: vec![ListAccountsFilter {
            name: ListAccountsFilterName::AccountId,
            values: vec!["999999999999".to_string()],
        }],
        max_items: None,
        marker: None,
    }
    .execute(&mut tx)
    .await
    .expect("Failed to list accounts with nonexistent account ID filter");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.accounts.len(), 0, "Expected no accounts for a nonexistent account ID");
    assert_eq!(resp.marker, None);
}

/// Create a user with only a name and account — all other fields take defaults.
async fn test_create_user_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "alice");
    assert_eq!(user.path, "/");
    assert!(user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert!(user.arn.ends_with(":user/alice"), "ARN must end with :user/alice, got {}", user.arn);
    assert!(user.permissions_boundary.is_none());
    assert!(user.tags.is_empty());
}

/// Create a user at a non-default path.
async fn test_create_user_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("bob".to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with path");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "bob");
    assert_eq!(user.path, "/engineering/");
    assert!(user.arn.ends_with(":user/engineering/bob"), "ARN must end with :user/engineering/bob, got {}", user.arn);
}

/// Create a user with tags attached.
async fn test_create_user_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("carol".to_string())
        .account_id("210987654321".to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Production".to_string())
                .build()
                .expect("Failed to build Environment tag"),
            Tag::builder()
                .key("Team".to_string())
                .value("Engineering".to_string())
                .build()
                .expect("Failed to build Team tag"),
        ])
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with tags");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "carol");
    assert_eq!(user.path, "/");
    assert_eq!(user.tags.len(), 2);
    assert_eq!(user.tags[0].key, "Environment");
    assert_eq!(user.tags[0].value, "Production");
    assert_eq!(user.tags[1].key, "Team");
    assert_eq!(user.tags[1].value, "Engineering");
}

/// Create a user with an existing managed policy as the permissions boundary.
async fn test_create_user_with_permissions_boundary(pool: &sqlx::PgPool) {
    // The test data has "Example-Managed-Policy-1" in account 123456789012 at path "/".

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateUserInternalRequest::builder()
        .user_name("dave".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/Example-Managed-Policy-1".to_string()))
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await
        .expect("Failed to create user with permissions boundary");
    tx.commit().await.expect("Failed to commit transaction");

    let user = resp.user.expect("Response should include created user");
    assert_eq!(user.user_name, "dave");
    let pb = user.permissions_boundary.expect("User should have a permissions boundary");
    let pb_arn = pb.permissions_boundary_arn.expect("Permissions boundary should include an ARN");
    assert_eq!(pb_arn, "arn:aws:iam::123456789012:policy/Example-Managed-Policy-1");
}

/// Attempting to create a user whose (lowercased) name already exists in the account must fail.
async fn test_create_user_duplicate_name(pool: &sqlx::PgPool) {
    // "alice" was committed by test_create_user_simple; re-inserting it must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate user name must fail");
}

/// Building a request with an invalid user name must fail before touching the database.
fn test_create_user_invalid_name() {
    // Spaces and `!` are not in the allowed character set.
    let result = CreateUserInternalRequest::builder()
        .user_name("bad name!".to_string())
        .account_id("123456789012".to_string())
        .build();
    assert!(result.is_err(), "Building a request with an invalid user name must fail");
}

/// Creating a user in an account that does not exist must fail with a FK violation.
async fn test_create_user_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("eve".to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a user in a nonexistent account must fail");
}

/// Specifying a permissions boundary that references a policy that does not exist must fail.
async fn test_create_user_nonexistent_permissions_boundary(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateUserInternalRequest::builder()
        .user_name("frank".to_string())
        .account_id("123456789012".to_string())
        .permissions_boundary(Some("arn:aws:iam::123456789012:policy/NonExistentPolicy".to_string()))
        .build()
        .expect("Failed to build CreateUserRequestInternal")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a user with a nonexistent permissions boundary must fail");
}

/// Tag an existing user and verify the tags appear in ListUserTags.
async fn test_tag_user(pool: &sqlx::PgPool) {
    // alice was created in account 123456789012 by test_create_user_simple.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder()
                .key("Dept".to_string())
                .value("Engineering".to_string())
                .build()
                .expect("Failed to build tag"),
            Tag::builder()
                .key("CostCenter".to_string())
                .value("1234".to_string())
                .build()
                .expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to tag user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify tags via ListUserTags.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListUserTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list user tags");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2, "Expected 2 tags on alice");
    // Tags are returned sorted by key_lower.
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
    assert_eq!(resp.tags[1].key, "Dept");
    assert_eq!(resp.tags[1].value, "Engineering");
}

/// Tagging with an existing key should update the value (upsert).
async fn test_tag_user_upsert(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder().key("Dept".to_string()).value("Finance".to_string()).build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to upsert tag on user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the value was updated and the other tag is still present.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListUserTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list user tags after upsert");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 2, "Expected 2 tags on alice after upsert");
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
    assert_eq!(resp.tags[1].key, "Dept");
    assert_eq!(resp.tags[1].value, "Finance");
}

/// Tagging a nonexistent user must fail with NoSuchEntityException.
async fn test_tag_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = TagUserInternalRequest::builder()
        .user_name("nonexistent".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![
            Tag::builder().key("Key".to_string()).value("Value".to_string()).build().expect("Failed to build tag"),
        ])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Tagging a nonexistent user must fail");
}

/// Tagging with an empty tag list must fail.
async fn test_tag_user_empty_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = TagUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tags(vec![])
        .build()
        .expect("Failed to build TagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Tagging with an empty tag list must fail");
}

/// Untag an existing user and verify the tag is removed.
async fn test_untag_user(pool: &sqlx::PgPool) {
    // alice currently has CostCenter and Dept tags from previous tests.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["Dept".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to untag user");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify only CostCenter remains.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListUserTagsInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListUserTagsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list user tags after untag");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.tags.len(), 1, "Expected 1 tag on alice after removing Dept");
    assert_eq!(resp.tags[0].key, "CostCenter");
    assert_eq!(resp.tags[0].value, "1234");
}

/// Untagging a key that does not exist on the user should succeed silently.
async fn test_untag_user_nonexistent_key(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["NoSuchTag".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Untagging a nonexistent key should succeed silently");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Untagging with an empty tag key list must fail.
async fn test_untag_user_empty_keys(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UntagUserInternalRequest::builder()
        .user_name("alice".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec![])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Untagging with an empty tag key list must fail");
}

/// Untagging a nonexistent user must fail with NoSuchEntityException.
async fn test_untag_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UntagUserInternalRequest::builder()
        .user_name("nonexistent".to_string())
        .account_id("123456789012".to_string())
        .tag_keys(vec!["Key".to_string()])
        .build()
        .expect("Failed to build UntagUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Untagging a nonexistent user must fail");
}

/// Get a user that exists with no tags (bob was created at /engineering/ with no tags).
async fn test_get_user_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserInternalRequest::builder()
        .user_name(Some("bob".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.user.user_name, "bob");
    assert_eq!(resp.user.path, "/engineering/");
    assert!(resp.user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert!(
        resp.user.arn.ends_with(":user/engineering/bob"),
        "ARN must end with :user/engineering/bob, got {}",
        resp.user.arn
    );
    assert!(resp.user.permissions_boundary.is_none());
    assert!(resp.user.tags.is_empty());
}

/// Get a user that has tags (alice has CostCenter tag after untag tests).
async fn test_get_user_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetUserInternalRequest::builder()
        .user_name(Some("alice".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.user.user_name, "alice");
    assert_eq!(resp.user.path, "/");
    assert!(resp.user.user_id.starts_with("AIDA"), "User ID must start with AIDA prefix");
    assert_eq!(resp.user.tags.len(), 1, "Expected 1 tag on alice");
    assert_eq!(resp.user.tags[0].key, "CostCenter");
    assert_eq!(resp.user.tags[0].value, "1234");
}

/// Getting a nonexistent user must fail.
async fn test_get_user_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetUserInternalRequest::builder()
        .user_name(Some("nonexistent".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a nonexistent user must fail");
}

/// Getting a user without providing a user name must fail.
async fn test_get_user_no_user_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a user without a user name must fail");
}

// -- Group tests -------------------------------------------------------------

/// Create a group with only a name and account — all other fields take defaults.
async fn test_create_group_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, "Admins");
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");
    assert!(resp.group.arn.ends_with(":group/Admins"), "ARN must end with :group/Admins, got {}", resp.group.arn);
}

/// Create a group at a non-default path.
async fn test_create_group_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group with path");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, "Developers");
    assert_eq!(resp.group.path, "/engineering/");
    assert!(
        resp.group.arn.ends_with(":group/engineering/Developers"),
        "ARN must end with :group/engineering/Developers, got {}",
        resp.group.arn
    );
}

/// Attempting to create a group whose (lowercased) name already exists in the account must fail.
async fn test_create_group_duplicate_name(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate group name must fail");
}

/// Creating a group in an account that does not exist must fail.
async fn test_create_group_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreateGroupInternalRequest::builder()
        .group_name("TestGroup".to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a group in a nonexistent account must fail");
}

/// Create a group with a 128-character name (the maximum allowed by AWS IAM).
async fn test_create_group_max_length_name(pool: &sqlx::PgPool) {
    // 128 characters: valid characters are [\w+=,.@-]
    let long_name = "A".repeat(128);
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreateGroupInternalRequest::builder()
        .group_name(long_name.clone())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create group with 128-character name");
    tx.commit().await.expect("Failed to commit transaction");

    assert_eq!(resp.group.group_name, long_name);
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");

    // Verify we can retrieve the group.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name(long_name.clone())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group with 128-character name");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, long_name);
}

/// Get a group that exists with default path.
async fn test_get_group_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Admins");
    assert_eq!(resp.group.path, "/");
    assert!(resp.group.group_id.starts_with("AGPA"), "Group ID must start with AGPA prefix");
    assert!(resp.group.arn.ends_with(":group/Admins"), "ARN must end with :group/Admins, got {}", resp.group.arn);
}

/// Get a group at a non-default path.
async fn test_get_group_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Developers");
    assert_eq!(resp.group.path, "/engineering/");
    assert!(
        resp.group.arn.ends_with(":group/engineering/Developers"),
        "ARN must end with :group/engineering/Developers, got {}",
        resp.group.arn
    );
}

/// Getting a nonexistent group must fail.
async fn test_get_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a nonexistent group must fail");
}

/// List groups in an account.
async fn test_list_groups(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsInternalRequest::builder()
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build ListGroupsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert!(resp.groups.len() >= 2, "Expected at least 2 groups, got {}", resp.groups.len());
    // Groups are sorted by name (lowercased).
    let names: Vec<&str> = resp.groups.iter().map(|g| g.group_name.as_str()).collect();
    assert!(names.contains(&"Admins"), "Expected Admins in group list");
    assert!(names.contains(&"Developers"), "Expected Developers in group list");
}

/// List groups with a path prefix filter.
async fn test_list_groups_with_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsInternalRequest::builder()
        .account_id("123456789012".to_string())
        .path_prefix(Some("/engineering/".to_string()))
        .build()
        .expect("Failed to build ListGroupsInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups with path prefix");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 1, "Expected exactly 1 group under /engineering/");
    assert_eq!(resp.groups[0].group_name, "Developers");
}

/// Rename a group.
async fn test_update_group_rename(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateGroupInternalRequest::builder()
        .group_name("Admins".to_string())
        .new_group_name(Some("Administrators".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to rename group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the rename took effect.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get renamed group");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.group_name, "Administrators");
}

/// Change the path of a group.
async fn test_update_group_change_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UpdateGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .new_path(Some("/admin/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to update group path");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the path change took effect.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetGroupInternalRequest::builder()
        .group_name("Administrators".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get group after path change");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.group.path, "/admin/");
}

/// Updating a nonexistent group must fail.
async fn test_update_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = UpdateGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .new_group_name(Some("NewName".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build UpdateGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Updating a nonexistent group must fail");
}

/// Delete the group with the maximum-length (128-character) name.
async fn test_delete_group_max_length_name(pool: &sqlx::PgPool) {
    let long_name = "A".repeat(128);
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupInternalRequest::builder()
        .group_name(long_name)
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete group with 128-character name");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Delete a group that exists.
async fn test_delete_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeleteGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify the group is gone.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = GetGroupInternalRequest::builder()
        .group_name("Developers".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build GetGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Getting a deleted group must fail");
}

/// Deleting a nonexistent group must fail.
async fn test_delete_group_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = DeleteGroupInternalRequest::builder()
        .group_name("NonexistentGroup".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build DeleteGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Deleting a nonexistent group must fail");
}

// -- Group membership tests --------------------------------------------------

/// Add a user to a group. Uses alice (account 123456789012) and Administrators (renamed earlier).
async fn test_add_user_to_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to add user to group");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Adding the same user to the same group again should succeed (idempotent).
async fn test_add_user_to_group_idempotent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Adding user to group again should succeed (idempotent)");
    tx.rollback().await.expect("Failed to rollback transaction");
}

/// Adding a user to a nonexistent group must fail.
async fn test_add_user_to_group_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("NonexistentGroup".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Adding user to nonexistent group must fail");
}

/// Adding a nonexistent user to a group must fail.
async fn test_add_user_to_group_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = AddUserToGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("nonexistent".to_string())
        .build()
        .expect("Failed to build AddUserToGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Adding nonexistent user to group must fail");
}

/// List groups for a user who is a member of at least one group.
async fn test_list_groups_for_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups for user");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 1, "Expected 1 group for alice");
    assert_eq!(resp.groups[0].group_name, "Administrators");
}

/// Listing groups for a nonexistent user must fail.
async fn test_list_groups_for_user_nonexistent_user(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("nonexistent".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Listing groups for nonexistent user must fail");
}

/// Remove a user from a group.
async fn test_remove_user_from_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to remove user from group");
    tx.commit().await.expect("Failed to commit transaction");

    // Verify alice is no longer in the group.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListGroupsForUserInternalRequest::builder()
        .account_id("123456789012".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build ListGroupsForUserInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list groups for user after removal");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(resp.groups.len(), 0, "Expected 0 groups for alice after removal");
}

/// Removing a user who is not a member of a group must fail.
async fn test_remove_user_from_group_not_member(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("Administrators".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Removing user who is not a group member must fail");
}

/// Removing a user from a nonexistent group must fail.
async fn test_remove_user_from_group_nonexistent_group(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = RemoveUserFromGroupInternalRequest::builder()
        .account_id("123456789012".to_string())
        .group_name("NonexistentGroup".to_string())
        .user_name("alice".to_string())
        .build()
        .expect("Failed to build RemoveUserFromGroupInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Removing user from nonexistent group must fail");
}

// -- CreatePolicyInternalRequest tests ----------------------------------------

const VALID_POLICY_DOCUMENT: &str =
    r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:GetObject","Resource":"*"}]}"#;

/// Create a simple managed policy with defaults.
async fn test_create_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("TestPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.policy_name.as_deref(), Some("TestPolicy"));
    assert_eq!(policy.path.as_deref(), Some("/"));
    assert!(
        policy.policy_id.as_ref().unwrap().starts_with("ANPA"),
        "Policy ID must start with ANPA prefix, got {:?}",
        policy.policy_id
    );
    assert!(
        policy.arn.as_ref().unwrap().ends_with(":policy/TestPolicy"),
        "ARN must end with :policy/TestPolicy, got {:?}",
        policy.arn
    );
    assert_eq!(policy.default_version_id.as_deref(), Some("v1"));
    assert_eq!(policy.is_attachable, Some(true));
    assert_eq!(policy.attachment_count, Some(0));
    assert_eq!(policy.permissions_boundary_usage_count, Some(0));
    assert!(policy.description.is_none());
    assert!(policy.tags.is_empty());
}

/// Create a policy with a non-default path.
async fn test_create_policy_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("PathPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy with path");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.path.as_deref(), Some("/engineering/"));
    assert!(
        policy.arn.as_ref().unwrap().ends_with(":policy/engineering/PathPolicy"),
        "ARN must end with :policy/engineering/PathPolicy, got {:?}",
        policy.arn
    );
}

/// Create a policy with a description.
async fn test_create_policy_with_description(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("DescribedPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .description(Some("Grants read access to S3 objects".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy with description");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.description.as_deref(), Some("Grants read access to S3 objects"));
}

/// Create a policy with tags.
async fn test_create_policy_with_tags(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = CreatePolicyInternalRequest::builder()
        .policy_name("TaggedPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .tags(vec![
            Tag::builder()
                .key("Environment".to_string())
                .value("Production".to_string())
                .build()
                .expect("Failed to build tag"),
            Tag::builder().key("Team".to_string()).value("Platform".to_string()).build().expect("Failed to build tag"),
        ])
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy with tags");
    tx.commit().await.expect("Failed to commit transaction");

    let policy = resp.policy.expect("Response should include created policy");
    assert_eq!(policy.tags.len(), 2, "Expected 2 tags on policy");
}

/// Creating a policy with a duplicate name must fail.
async fn test_create_policy_duplicate_name(pool: &sqlx::PgPool) {
    // "TestPolicy" was committed by test_create_policy_simple; re-inserting must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("TestPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a duplicate policy name must fail");
}

/// Creating a policy with an invalid policy document must fail.
async fn test_create_policy_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("BadDocPolicy".to_string())
        .policy_document("not valid json".to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy with an invalid document must fail");
}

/// Creating a policy with valid JSON that is not a valid Aspen policy must fail.
async fn test_create_policy_valid_json_invalid_aspen(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("ValidJsonBadAspen".to_string())
        .policy_document(r#"{"foo": "bar"}"#.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy with valid JSON but invalid Aspen document must fail");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("ValidJsonBadAspen".to_string())
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Action":"s3:GetObject","Resource":"*"}]}"#.to_string(),
        )
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy with valid JSON but invalid Aspen document must fail");
}

/// Creating a policy in an account that does not exist must fail.
async fn test_create_policy_nonexistent_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyInternalRequest::builder()
        .policy_name("OrphanPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("999999999999".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a policy in a nonexistent account must fail");
}

/// Create a new policy version with set_as_default = true (default behavior).
async fn test_create_policy_version_simple(pool: &sqlx::PgPool) {
    // First, create a policy to add versions to.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("VersionedPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy");
    tx.commit().await.expect("Failed to commit transaction");

    // Now create a new version.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let new_document =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    let resp = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(new_document.to_string())
        .set_as_default(Some(true))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version");
    tx.commit().await.expect("Failed to commit transaction");

    let pv = resp.policy_version.expect("Response should include policy version");
    assert_eq!(pv.version_id.as_deref(), Some("v2"));
    assert_eq!(pv.is_default_version, Some(true));
    assert_eq!(pv.document.as_deref(), Some(new_document));
    assert!(pv.create_date.is_some());
}

/// Create a policy version with set_as_default = true explicitly.
async fn test_create_policy_version_set_as_default(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let new_document =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}"#;
    let resp = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(new_document.to_string())
        .set_as_default(Some(true))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version as default");
    tx.commit().await.expect("Failed to commit transaction");

    let pv = resp.policy_version.expect("Response should include policy version");
    assert_eq!(pv.version_id.as_deref(), Some("v3"));
    assert_eq!(pv.is_default_version, Some(true));
}

/// Create a policy version with set_as_default = false.
async fn test_create_policy_version_not_default(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let new_document =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:DescribeInstances","Resource":"*"}]}"#;
    let resp = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(new_document.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version (not default)");
    tx.commit().await.expect("Failed to commit transaction");

    let pv = resp.policy_version.expect("Response should include policy version");
    assert_eq!(pv.version_id.as_deref(), Some("v4"));
    assert_eq!(pv.is_default_version, Some(false));
}

/// Exceeding 5 versions must fail with LimitExceededException.
async fn test_create_policy_version_limit_exceeded(pool: &sqlx::PgPool) {
    // v1 was created with the policy, v2-v4 above. Create v5.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let doc_v5 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"ec2:RunInstances","Resource":"*"}]}"#;
    CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(doc_v5.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy version v5");
    tx.commit().await.expect("Failed to commit transaction");

    // Now attempt to create v6, which must fail.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let doc_v6 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"ec2:TerminateInstances","Resource":"*"}]}"#;
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document(doc_v6.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a 6th policy version must fail");
}

/// Creating a version for a nonexistent policy must fail.
async fn test_create_policy_version_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchPolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a version for a nonexistent policy must fail");
}

/// Creating a version with an ARN whose path does not match the policy path must fail.
async fn test_create_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("PathSensitivePolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/wrong/PathSensitivePolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a version with a mismatched path must fail");
}

/// Creating a version with an invalid policy document must fail.
async fn test_create_policy_version_invalid_document(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let result = CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .policy_document("not valid json".to_string())
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await;
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(result.is_err(), "Creating a version with an invalid document must fail");
}

/// Delete a non-default version of a managed policy. After the test_create_policy_version_*
/// tests, "VersionedPolicy" has versions v1..v5 with v3 as the default version. v1 is not the
/// default, so deleting it should succeed.
async fn test_delete_policy_version_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete policy version v1");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting the same version should fail with NoSuchEntity since the row is gone.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Re-deleting v1 should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting the default version must fail with DeleteConflictException.
async fn test_delete_policy_version_default_fails(pool: &sqlx::PgPool) {
    // v3 is the default version of VersionedPolicy.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting the default version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");

    // Confirm v3 is still present by trying to delete it again (still must fail with DeleteConflict).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Default version still cannot be deleted on a retry");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

/// Deleting a version on a policy with a non-default path must work when the ARN's path matches.
async fn test_delete_policy_version_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("PathDelVersion".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .path(Some("/engineering/".to_string()))
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create policy at /engineering/PathDelVersion");
    let doc_v2 = r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#;
    CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathDelVersion".to_string())
        .policy_document(doc_v2.to_string())
        .set_as_default(Some(true))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v2 of /engineering/PathDelVersion");
    tx.commit().await.expect("Failed to commit transaction");

    // v1 is no longer the default; delete it.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathDelVersion".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v1 of /engineering/PathDelVersion");
    tx.commit().await.expect("Failed to commit transaction");
}

/// Deleting a version using an ARN with the wrong path must fail with NoSuchEntity.
async fn test_delete_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    // PathDelVersion lives at /engineering/, not at /.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/PathDelVersion".to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting with a mismatched path must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting a version from a policy that does not exist must fail with NoSuchEntity.
async fn test_delete_policy_version_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchPolicyEver".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a version of a nonexistent policy must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting a version that does not exist on an existing policy must fail with NoSuchEntity.
async fn test_delete_policy_version_nonexistent_version(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v99".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting a nonexistent version must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// Deleting with an unparseable ARN must fail with ValidationError.
async fn test_delete_policy_version_invalid_arn(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    // 20+ character invalid ARN to pass the Smithy length check but fail ARN parsing.
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("not-an-arn-but-long-enough-to-pass".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting with an invalid ARN must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");

    // An ARN whose resource does not start with "policy/" must also fail with ValidationError.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:user/SomeUser".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Deleting with a non-policy ARN must fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

/// Deleting a version on an AWS-owned managed policy must accept an "aws" account in the ARN
/// (mapped to "000000000000").
async fn test_delete_policy_version_aws_account(pool: &sqlx::PgPool) {
    // CreatePolicy's Smithy regex requires a 12-digit account id, so create the AWS-owned policy
    // by addressing it with the literal "000000000000" account that bootstrap inserts.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    CreatePolicyInternalRequest::builder()
        .policy_name("AwsOwnedDelVersion".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("000000000000".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create AWS-owned policy");
    let doc_v2 =
        r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteBucket","Resource":"*"}]}"#;
    CreatePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::000000000000:policy/AwsOwnedDelVersion".to_string())
        .policy_document(doc_v2.to_string())
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v2 of AwsOwnedDelVersion");
    tx.commit().await.expect("Failed to commit transaction");

    // Delete v2 using "aws" in the ARN.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v2 of AwsOwnedDelVersion via 'aws' account");
    tx.commit().await.expect("Failed to commit transaction");

    // Re-deleting the same version should fail with NoSuchEntity (proves it really was deleted
    // from the "000000000000" account row).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Re-deleting v2 should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");

    // Also verify that the same ARN using "000000000000" addresses the same policy.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = DeletePolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::000000000000:policy/AwsOwnedDelVersion".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("v1 is the default and cannot be deleted");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::DeleteConflictException(_)), "Expected DeleteConflict, got: {err:?}");
}

// -- GetPolicy / GetPolicyVersion tests ----------------------------------------

async fn test_get_policy_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("TestPolicy"));
    assert_eq!(policy.path.as_deref(), Some("/"));
    assert_eq!(policy.default_version_id.as_deref(), Some("v1"));
    assert_eq!(policy.is_attachable, Some(true));
    assert_eq!(policy.arn.as_deref(), Some("arn:test-partition:iam::123456789012:policy/TestPolicy"));
    assert!(policy.tags.is_empty());
    assert!(policy.policy_id.as_ref().unwrap().starts_with("ANPA"));
    assert!(policy.create_date.is_some());
    assert!(policy.update_date.is_some());
}

async fn test_get_policy_with_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/PathPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get PathPolicy at /engineering/");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("PathPolicy"));
    assert_eq!(policy.path.as_deref(), Some("/engineering/"));
}

/// Look up the AWS-owned policy created earlier in the delete tests by using "aws" in the ARN.
async fn test_get_policy_aws_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get AwsOwnedDelVersion via 'aws' account");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    assert_eq!(policy.policy_name.as_deref(), Some("AwsOwnedDelVersion"));
}

async fn test_get_policy_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/TestPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get with mismatched path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

async fn test_get_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchGetPolicy".to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// VersionedPolicy has v3 as default after CreatePolicyVersion tests.
async fn test_get_policy_version_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get v3 of VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let pv = resp.policy_version.expect("Response should include policy_version");
    assert_eq!(pv.version_id.as_deref(), Some("v3"));
    assert_eq!(pv.is_default_version, Some(true));
    assert!(pv.document.is_some());
    assert!(pv.create_date.is_some());

    // Also fetch a non-default version (v4 was created non-default in CreatePolicyVersion tests).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v4".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get v4 of VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let pv = resp.policy_version.expect("Response should include policy_version");
    assert_eq!(pv.version_id.as_deref(), Some("v4"));
    assert_eq!(pv.is_default_version, Some(false));
}

async fn test_get_policy_version_nonexistent_version(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v99".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get nonexistent version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

async fn test_get_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = GetPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/VersionedPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build GetPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Get with wrong path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- SetDefaultPolicyVersion tests --------------------------------------------

/// VersionedPolicy currently has v3 as default. Set it to v4, verify, then back to v3.
async fn test_set_default_policy_version_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/VersionedPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    SetDefaultPolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v4".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to set default to v4");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert_eq!(resp.policy.unwrap().default_version_id.as_deref(), Some("v4"));

    // Restore v3 as default so later list tests see a stable state.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    SetDefaultPolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to restore default to v3");
    tx.commit().await.expect("Failed to commit transaction");
}

async fn test_set_default_policy_version_nonexistent_version(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .version_id("v99".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Set default to nonexistent version should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

async fn test_set_default_policy_version_nonexistent_policy(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchSetDefaultPolicy".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Set default on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

async fn test_set_default_policy_version_mismatched_path(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/engineering/VersionedPolicy".to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect_err("Set default with mismatched path should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

/// AwsOwnedDelVersion has only v1 in account 000000000000. Setting v1 as default through 'aws'
/// ARN should succeed (idempotent).
async fn test_set_default_policy_version_aws_account(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    SetDefaultPolicyVersionRequest::builder()
        .policy_arn("arn:test-partition:iam::aws:policy/AwsOwnedDelVersion".to_string())
        .version_id("v1".to_string())
        .build()
        .expect("Failed to build SetDefaultPolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to set default via 'aws' ARN");
    tx.commit().await.expect("Failed to commit transaction");
}

// -- TagPolicy / UntagPolicy tests --------------------------------------------

async fn test_tag_policy_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/TestPolicy";
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .tags(vec![
            Tag::builder().key("Env".to_string()).value("Prod".to_string()).build().expect("Tag build failed"),
            Tag::builder().key("Owner".to_string()).value("Platform".to_string()).build().expect("Tag build failed"),
        ])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to tag TestPolicy");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy after tagging");
    tx.rollback().await.expect("Failed to rollback transaction");

    let policy = resp.policy.expect("Response should include policy");
    let tag_pairs: Vec<(String, String)> = policy.tags.iter().map(|t| (t.key.clone(), t.value.clone())).collect();
    assert!(tag_pairs.contains(&("Env".to_string(), "Prod".to_string())));
    assert!(tag_pairs.contains(&("Owner".to_string(), "Platform".to_string())));
}

async fn test_tag_policy_upsert(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/TestPolicy";

    // Update Env=Prod to Env=Staging.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    TagPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .tags(vec![
            Tag::builder().key("Env".to_string()).value("Staging".to_string()).build().expect("Tag build failed"),
        ])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to upsert tag");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let env_value = resp
        .policy
        .unwrap()
        .tags
        .iter()
        .find(|t| t.key == "Env")
        .map(|t| t.value.clone())
        .expect("Env tag should exist");
    assert_eq!(env_value, "Staging");
}

async fn test_tag_policy_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = TagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy".to_string())
        .tags(vec![])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Tagging with empty list should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

async fn test_tag_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = TagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchTagPolicy".to_string())
        .tags(vec![Tag::builder().key("X".to_string()).value("Y".to_string()).build().expect("Tag build failed")])
        .build()
        .expect("Failed to build TagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Tagging missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

async fn test_untag_policy_simple(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/TestPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    UntagPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .tag_keys(vec!["Owner".to_string()])
        .build()
        .expect("Failed to build UntagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to untag Owner");
    tx.commit().await.expect("Failed to commit transaction");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get TestPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    let keys: Vec<String> = resp.policy.unwrap().tags.iter().map(|t| t.key.clone()).collect();
    assert!(!keys.contains(&"Owner".to_string()), "Owner tag should have been removed");
    assert!(keys.contains(&"Env".to_string()), "Env tag should still be present");
}

async fn test_untag_policy_empty(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UntagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/TestPolicy".to_string())
        .tag_keys(vec![])
        .build()
        .expect("Failed to build UntagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Untagging with empty list should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::ValidationError(_)), "Expected ValidationError, got: {err:?}");
}

async fn test_untag_policy_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = UntagPolicyRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchUntagPolicy".to_string())
        .tag_keys(vec!["X".to_string()])
        .build()
        .expect("Failed to build UntagPolicyRequest")
        .execute(&mut tx)
        .await
        .expect_err("Untagging missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

// -- ListPolicyVersions tests -------------------------------------------------

async fn test_list_policy_versions_simple(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPolicyVersionsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/VersionedPolicy".to_string())
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list versions of VersionedPolicy");
    tx.rollback().await.expect("Failed to rollback transaction");

    // VersionedPolicy has v2..v5 after v1 was deleted in delete tests.
    let version_ids: Vec<String> = resp.versions.iter().filter_map(|v| v.version_id.clone()).collect();
    assert_eq!(version_ids, vec!["v5".to_string(), "v4".to_string(), "v3".to_string(), "v2".to_string()]);

    // v3 should be marked as the default.
    let v3 = resp.versions.iter().find(|v| v.version_id.as_deref() == Some("v3")).expect("v3 should exist");
    assert_eq!(v3.is_default_version, Some(true));
    let v4 = resp.versions.iter().find(|v| v.version_id.as_deref() == Some("v4")).expect("v4 should exist");
    assert_eq!(v4.is_default_version, Some(false));
}

async fn test_list_policy_versions_nonexistent(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let err = ListPolicyVersionsRequest::builder()
        .policy_arn("arn:test-partition:iam::123456789012:policy/NoSuchListVersions".to_string())
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect_err("List versions on missing policy should fail");
    tx.rollback().await.expect("Failed to rollback transaction");
    assert!(matches!(err, IamError::NoSuchEntityException(_)), "Expected NoSuchEntity, got: {err:?}");
}

async fn test_list_policy_versions_pagination(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/VersionedPolicy";

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page1 = ListPolicyVersionsRequest::builder()
        .policy_arn(arn.to_string())
        .max_items(Some(2))
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list page 1");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page1.versions.len(), 2);
    assert_eq!(page1.is_truncated, Some(true));
    let marker = page1.marker.expect("Page 1 should have a marker");

    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let page2 = ListPolicyVersionsRequest::builder()
        .policy_arn(arn.to_string())
        .max_items(Some(2))
        .marker(Some(marker))
        .build()
        .expect("Failed to build ListPolicyVersionsRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list page 2");
    tx.rollback().await.expect("Failed to rollback transaction");

    assert_eq!(page2.versions.len(), 2);
    let all: Vec<String> =
        page1.versions.iter().chain(page2.versions.iter()).filter_map(|v| v.version_id.clone()).collect();
    assert_eq!(all, vec!["v5".to_string(), "v4".to_string(), "v3".to_string(), "v2".to_string()]);
}

// -- ListPolicies tests -------------------------------------------------------

async fn test_list_policies_local(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Local))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list local policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"TestPolicy".to_string()), "Expected TestPolicy in local list: {names:?}");
    assert!(names.contains(&"Example-Managed-Policy-1".to_string()), "Expected Example-Managed-Policy-1: {names:?}");
    assert!(names.iter().all(|n| n != "AwsOwnedDelVersion"), "AwsOwnedDelVersion should not be local for this account");
}

async fn test_list_policies_aws(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Aws))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list AWS-scope policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"AwsOwnedDelVersion".to_string()), "Expected AwsOwnedDelVersion in AWS-scope: {names:?}");
    assert!(names.iter().all(|n| n != "TestPolicy"), "TestPolicy is customer-managed and must not appear");
}

async fn test_list_policies_all(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list all policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"TestPolicy".to_string()));
    assert!(names.contains(&"AwsOwnedDelVersion".to_string()));
}

async fn test_list_policies_path_prefix(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::Local))
        .path_prefix(Some("/engineering/".to_string()))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list policies with /engineering/ path");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"PathPolicy".to_string()), "Expected PathPolicy: {names:?}");
    assert!(names.contains(&"PathDelVersion".to_string()), "Expected PathDelVersion: {names:?}");
    for policy in &resp.policies {
        assert_eq!(policy.path.as_deref(), Some("/engineering/"));
    }
}

/// Example-Managed-Policy-1 (AAAABBBBCCCCDDDD) is attached to EXAMPLEUSERID456 via the seeded
/// test data, so it should appear when only_attached=true.
async fn test_list_policies_only_attached(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .only_attached(Some(true))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list attached policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"Example-Managed-Policy-1".to_string()), "Expected Example-Managed-Policy-1: {names:?}");
    // None of the freshly-created policies are attached to a user/role/group.
    assert!(!names.contains(&"TestPolicy".to_string()), "TestPolicy is not attached and should not appear");
}

/// Example-Managed-Policy-1 is also the permissions boundary of EXAMPLEUSERID123, so it should
/// appear when filtering for PermissionsBoundary usage.
async fn test_list_policies_usage_filter_pb(pool: &sqlx::PgPool) {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = ListPoliciesInternalRequest::builder()
        .account_id("123456789012".to_string())
        .scope(Some(PolicyScopeType::All))
        .policy_usage_filter(Some(PolicyUsageType::PermissionsBoundary))
        .max_items(Some(1000))
        .build()
        .expect("Failed to build ListPoliciesInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to list PB policies");
    tx.rollback().await.expect("Failed to rollback transaction");

    let names: Vec<String> = resp.policies.iter().filter_map(|p| p.policy_name.clone()).collect();
    assert!(names.contains(&"Example-Managed-Policy-1".to_string()), "Expected Example-Managed-Policy-1: {names:?}");

    // TestPolicy is unattached and not used as a permissions boundary, so it should not appear.
    assert!(
        !names.contains(&"TestPolicy".to_string()),
        "TestPolicy is not used as a permissions boundary and should not appear"
    );
}

// -- update_date denormalization tests ----------------------------------------

/// Exercise update_date semantics across CreatePolicy, CreatePolicyVersion, and
/// DeletePolicyVersion (both for non-latest and latest versions). update_date is supposed to
/// track the most recent version's created_at.
async fn test_policy_update_date_lifecycle(pool: &sqlx::PgPool) {
    let arn = "arn:test-partition:iam::123456789012:policy/UpdateDatePolicy";

    // Create the policy. Initially the only version is v1, so update_date == v1.create_date.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let create = CreatePolicyInternalRequest::builder()
        .policy_name("UpdateDatePolicy".to_string())
        .policy_document(VALID_POLICY_DOCUMENT.to_string())
        .account_id("123456789012".to_string())
        .build()
        .expect("Failed to build CreatePolicyInternalRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create UpdateDatePolicy");
    tx.commit().await.expect("Failed to commit transaction");

    let initial_update_date = get_policy_update_date(pool, arn).await;
    // CreatePolicy doesn't return update_date directly, but it must equal the policy's create_date,
    // which is the version's created_at (they all come from the same CURRENT_TIMESTAMP in-tx).
    assert_eq!(initial_update_date, create.policy.as_ref().unwrap().create_date.unwrap());

    // Create v2 (non-default). update_date should advance to v2.create_date.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let v2 = CreatePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Action":"s3:PutObject","Resource":"*"}]}"#
                .to_string(),
        )
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v2");
    tx.commit().await.expect("Failed to commit transaction");

    let after_v2 = get_policy_update_date(pool, arn).await;
    assert_eq!(after_v2, v2.policy_version.as_ref().unwrap().create_date.unwrap());
    assert!(after_v2 > initial_update_date, "update_date should advance after CreatePolicyVersion");

    // Create v3 (non-default). update_date should advance to v3.create_date.
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let v3 = CreatePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .policy_document(
            r#"{"Version":"2012-10-17","Statement":[{"Effect":"Deny","Action":"s3:DeleteObject","Resource":"*"}]}"#
                .to_string(),
        )
        .set_as_default(Some(false))
        .build()
        .expect("Failed to build CreatePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to create v3");
    tx.commit().await.expect("Failed to commit transaction");
    let v3_create_date = v3.policy_version.as_ref().unwrap().create_date.unwrap();
    assert_eq!(get_policy_update_date(pool, arn).await, v3_create_date);

    // Delete v2 (non-latest). update_date should be unchanged (still v3.create_date).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v2".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v2");
    tx.commit().await.expect("Failed to commit transaction");
    assert_eq!(
        get_policy_update_date(pool, arn).await,
        v3_create_date,
        "Deleting a non-latest version must not change update_date"
    );

    // Delete v3 (the latest). update_date should be recomputed to v1.create_date (only remaining).
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    DeletePolicyVersionRequest::builder()
        .policy_arn(arn.to_string())
        .version_id("v3".to_string())
        .build()
        .expect("Failed to build DeletePolicyVersionRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to delete v3");
    tx.commit().await.expect("Failed to commit transaction");
    assert_eq!(
        get_policy_update_date(pool, arn).await,
        initial_update_date,
        "Deleting the latest version must roll update_date back to the now-latest version's create_date"
    );
}

/// Fetch the `update_date` for a managed policy via GetPolicy.
async fn get_policy_update_date(pool: &sqlx::PgPool, arn: &str) -> chrono::DateTime<chrono::Utc> {
    let mut tx = pool.begin().await.expect("Failed to begin transaction");
    let resp = GetPolicyRequest::builder()
        .policy_arn(arn.to_string())
        .build()
        .expect("Failed to build GetPolicyRequest")
        .execute(&mut tx)
        .await
        .expect("Failed to get policy");
    tx.rollback().await.expect("Failed to rollback transaction");
    resp.policy.unwrap().update_date.expect("Policy should have update_date")
}

const TEST_DATA: &str = include_str!("iam_database.json");
